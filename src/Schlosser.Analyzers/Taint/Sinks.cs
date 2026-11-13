using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Operations;

namespace Schlosser.Taint;

/// <summary>One dangerous use: the value that must not be attacker-controlled, and what it is passed to.</summary>
internal readonly struct SinkUse
{
    public SinkUse(SinkKind kind, IOperation value, string name)
    {
        Kind = kind;
        Value = value;
        Name = name;
    }

    public SinkKind Kind { get; }
    public IOperation Value { get; }
    /// <summary>For messages, e.g. "SqlCommand.CommandText" or "File.ReadAllText".</summary>
    public string Name { get; }
}

/// <summary>The dangerous calls, matched by type and parameter name so that every overload is covered.</summary>
internal static class Sinks
{
    public static void Find(IOperation operation, List<SinkUse> into)
    {
        switch (operation)
        {
            case IInvocationOperation invocation:
                FromCall(invocation.TargetMethod, invocation.Arguments, into);
                break;
            case IObjectCreationOperation { Constructor: { } constructor } creation:
                FromCall(constructor, creation.Arguments, into);
                break;
            case ISimpleAssignmentOperation { Target: IPropertyReferenceOperation target } assignment:
                FromAssignment(target.Property, assignment.Value, into);
                break;
        }
    }

    private static void FromAssignment(IPropertySymbol property, IOperation value, List<SinkUse> into)
    {
        var type = property.ContainingType;
        if (type is null) return;
        var kind = SinkKind.None;

        switch (property.Name)
        {
            case "CommandText" when type.IsOrImplements("System.Data.IDbCommand"):
                kind = SinkKind.Sql;
                break;
            case "FileName" or "Arguments" when type.Is("System.Diagnostics.ProcessStartInfo"):
                kind = SinkKind.Command;
                break;
            case "Filter" when type.Is("System.DirectoryServices.DirectorySearcher")
                               || type.Is("System.DirectoryServices.Protocols.SearchRequest"):
                kind = SinkKind.Ldap;
                break;
            case "BaseAddress" when type.InheritsFrom("System.Net.Http.HttpClient"):
            case "RequestUri" when type.Is("System.Net.Http.HttpRequestMessage"):
                kind = SinkKind.Ssrf;
                break;
        }

        if (kind != SinkKind.None) into.Add(new SinkUse(kind, value, type.Name + "." + property.Name));
    }

    private static void FromCall(IMethodSymbol method, ImmutableArray<IArgumentOperation> arguments, List<SinkUse> into)
    {
        var type = method.ContainingType;
        if (type is null || arguments.IsEmpty) return;
        var name = method.Short();

        if (IsSqlApi(type))
        {
            foreach (var argument in arguments)
                if (IsString(argument) && argument.Parameter!.Name is "sql" or "commandText" or "cmdText" or "selectCommandText")
                    into.Add(new SinkUse(SinkKind.Sql, argument.Value, name));
            return;
        }

        switch (type.Name)
        {
            case "Process" when method.Name == "Start" && type.Is("System.Diagnostics.Process"):
            case "ProcessStartInfo" when method.MethodKind == MethodKind.Constructor && type.Is("System.Diagnostics.ProcessStartInfo"):
                foreach (var argument in arguments)
                    if (IsString(argument)) into.Add(new SinkUse(SinkKind.Command, argument.Value, name));
                return;

            case "File" or "Directory" when type.Is("System.IO.File") || type.Is("System.IO.Directory"):
                AddPathArguments(arguments, name, into);
                return;

            case "FileStream" or "StreamReader" or "StreamWriter" or "FileInfo" or "DirectoryInfo"
                when method.MethodKind == MethodKind.Constructor && type.ContainingNamespace?.ToDisplayString() == "System.IO":
                AddPathArguments(arguments, name, into);
                return;

            case "Regex" when type.Is("System.Text.RegularExpressions.Regex"):
                AddRegex(arguments, name, into);
                return;

            case "HtmlString" when method.MethodKind == MethodKind.Constructor && type.Is("Microsoft.AspNetCore.Html.HtmlString"):
            case "MarkupString" when method.MethodKind == MethodKind.Constructor && type.Is("Microsoft.AspNetCore.Components.MarkupString"):
                into.Add(new SinkUse(SinkKind.Xss, arguments[0].Value, name));
                return;

            case "RedirectResult" when method.MethodKind == MethodKind.Constructor:
                into.Add(new SinkUse(SinkKind.Redirect, arguments[0].Value, name));
                return;

            case "HttpRequestMessage" when method.MethodKind == MethodKind.Constructor && type.Is("System.Net.Http.HttpRequestMessage"):
            case "WebRequest" when method.Name is "Create" or "CreateHttp" && type.Is("System.Net.WebRequest"):
                foreach (var argument in arguments)
                    if (argument.Parameter?.Name is "requestUri" or "requestUriString")
                        into.Add(new SinkUse(SinkKind.Ssrf, argument.Value, name));
                return;

            case "WebClient" when type.Is("System.Net.WebClient"):
                foreach (var argument in arguments)
                    if (argument.Parameter?.Name == "address") into.Add(new SinkUse(SinkKind.Ssrf, argument.Value, name));
                return;

            case "DirectorySearcher" when method.MethodKind == MethodKind.Constructor:
            case "SearchRequest" when method.MethodKind == MethodKind.Constructor:
                foreach (var argument in arguments)
                    if (argument.Parameter?.Name is "filter" or "ldapFilter")
                        into.Add(new SinkUse(SinkKind.Ldap, argument.Value, name));
                return;
        }

        switch (method.Name)
        {
            case "Redirect" or "RedirectPermanent" or "RedirectPreserveMethod" or "RedirectPermanentPreserveMethod"
                when type.InheritsFrom("Microsoft.AspNetCore.Mvc.ControllerBase")
                     || type.InheritsFrom("Microsoft.AspNetCore.Mvc.RazorPages.PageModel")
                     || type.Is("Microsoft.AspNetCore.Http.HttpResponse")
                     || type.Is("Microsoft.AspNetCore.Http.Results")
                     || type.Is("Microsoft.AspNetCore.Http.TypedResults"):
                into.Add(new SinkUse(SinkKind.Redirect, arguments[0].Value, name));
                return;

            case "PhysicalFile"
                when type.InheritsFrom("Microsoft.AspNetCore.Mvc.ControllerBase")
                     || type.InheritsFrom("Microsoft.AspNetCore.Mvc.RazorPages.PageModel")
                     || type.Is("Microsoft.AspNetCore.Http.TypedResults"):
            case "File" when type.Is("Microsoft.AspNetCore.Http.Results") && arguments[0].Parameter?.Name == "path":
                into.Add(new SinkUse(SinkKind.Path, arguments[0].Value, name));
                return;

            case "Raw" when type.IsOrImplements("Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper"):
                into.Add(new SinkUse(SinkKind.Xss, arguments[0].Value, name));
                return;

            case "Content" or "Text"
                when type.InheritsFrom("Microsoft.AspNetCore.Mvc.ControllerBase")
                     || type.InheritsFrom("Microsoft.AspNetCore.Mvc.RazorPages.PageModel")
                     || type.Is("Microsoft.AspNetCore.Http.Results")
                     || type.Is("Microsoft.AspNetCore.Http.TypedResults"):
                // Only HTML responses: Content(text) alone is text/plain
                foreach (var argument in arguments)
                {
                    if (argument.Parameter?.Name == "contentType"
                        && argument.Value.ConstantValue is { HasValue: true, Value: string contentType }
                        && contentType.IndexOf("html", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        into.Add(new SinkUse(SinkKind.Xss, arguments[0].Value, name + " (text/html)"));
                    }
                }
                return;

            case "SelectNodes" or "SelectSingleNode" or "Select" or "Evaluate" or "Compile"
                or "XPathSelectElement" or "XPathSelectElements" or "XPathEvaluate"
                when type.ContainingNamespace?.ToDisplayString() is "System.Xml" or "System.Xml.XPath":
                foreach (var argument in arguments)
                    if (IsString(argument) && argument.Parameter!.Name is "xpath" or "expression")
                        into.Add(new SinkUse(SinkKind.XPath, argument.Value, name));
                return;
        }

        // HttpClient.GetAsync(requestUri), GetStringAsync, PostAsync, GetFromJsonAsync, PostAsJsonAsync ...
        if (type.InheritsFrom("System.Net.Http.HttpClient") || type.Name is "HttpClientJsonExtensions")
        {
            foreach (var argument in arguments)
                if (argument.Parameter?.Name == "requestUri") into.Add(new SinkUse(SinkKind.Ssrf, argument.Value, name));
        }
    }

    private static bool IsSqlApi(INamedTypeSymbol type)
    {
        switch (type.Name)
        {
            case "RelationalDatabaseFacadeExtensions":
            case "RelationalQueryableExtensions":
                return type.ContainingNamespace?.ToDisplayString() == "Microsoft.EntityFrameworkCore";
            case "SqlMapper":
            case "CommandDefinition":
                return type.ContainingNamespace?.ToDisplayString() == "Dapper";
        }

        return type.IsOrImplements("System.Data.IDbCommand") || type.IsOrImplements("System.Data.IDbDataAdapter");
    }

    private static void AddPathArguments(ImmutableArray<IArgumentOperation> arguments, string name, List<SinkUse> into)
    {
        foreach (var argument in arguments)
        {
            if (!IsString(argument)) continue;
            var parameter = argument.Parameter!.Name;
            if (parameter.IndexOf("path", StringComparison.OrdinalIgnoreCase) >= 0
                || parameter.IndexOf("fileName", StringComparison.OrdinalIgnoreCase) >= 0)
                into.Add(new SinkUse(SinkKind.Path, argument.Value, name));
        }
    }

    private static void AddRegex(ImmutableArray<IArgumentOperation> arguments, string name, List<SinkUse> into)
    {
        IOperation? pattern = null;
        foreach (var argument in arguments)
        {
            var parameter = argument.Parameter;
            if (parameter is null) continue;
            if (parameter.Type.Name == "TimeSpan" && !argument.IsImplicit) return; // has a match timeout
            if (parameter.Name == "options" && argument.Value.ConstantValue is { HasValue: true, Value: int options }
                                            && (options & 1024) != 0) return; // RegexOptions.NonBacktracking
            if (parameter.Name == "pattern") pattern = argument.Value;
        }

        if (pattern is not null) into.Add(new SinkUse(SinkKind.Regex, pattern, name));
    }

    private static bool IsString(IArgumentOperation argument) =>
        argument.Parameter is { Type.SpecialType: SpecialType.System_String };
}
