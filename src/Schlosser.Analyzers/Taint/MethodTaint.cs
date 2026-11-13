using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Operations;

namespace Schlosser.Taint;

/// <summary>
/// Taint analysis of one method body. It is flow-insensitive: a variable is tainted if any assignment to it is.
/// That is simpler than a full data-flow analysis, never misses a reassignment, and is fast enough to run on every build.
/// </summary>
internal sealed class MethodTaint
{
    private readonly Dictionary<ISymbol, TaintValue> _variables = new(SymbolEqualityComparer.Default);
    private readonly Dictionary<ISymbol, List<IOperation>> _assigned = new(SymbolEqualityComparer.Default);
    private readonly List<(ISymbol Target, IOperation Value)> _flows = new();
    private readonly HashSet<string> _calledNames = new(StringComparer.Ordinal);

    public MethodTaint(ISymbol owner, ImmutableArray<IOperation> blocks)
    {
        Method = owner as IMethodSymbol;
        IsEntryPoint = Method is not null && EntryPoints.IsEntryPoint(Method);

        if (Method is not null)
        {
            foreach (var parameter in Method.Parameters)
            {
                if (IsEntryPoint)
                {
                    if (EntryPoints.IsBound(parameter, minimalApi: false))
                        _variables[parameter] = TaintValue.FromRequest($"parameter '{parameter.Name}' of {Method.Short()}");
                }
                else if (parameter.Ordinal < 64 && Carrier.CanCarry(parameter.Type))
                {
                    _variables[parameter] = TaintValue.FromParameter(parameter.Ordinal);
                }
            }
        }

        foreach (var block in blocks)
            foreach (var operation in block.DescendantsAndSelf())
                Collect(operation);

        // Fixed point: repeat until no variable changes any more
        for (var round = 0; round < 12; round++)
        {
            var changed = false;
            foreach (var (target, value) in _flows)
            {
                var incoming = Of(value);
                if (incoming.IsNone) continue;
                _variables.TryGetValue(target, out var before);
                var after = before.Union(incoming);
                if (after.Equals(before)) continue;
                _variables[target] = after;
                changed = true;
            }

            if (!changed) break;
        }
    }

    public IMethodSymbol? Method { get; }
    public bool IsEntryPoint { get; }

    /// <summary>Methods handed to MapGet/MapPost as a method group: their parameters are filled from the request.</summary>
    public List<(IMethodSymbol Handler, Location Location)> EndpointMethodGroups { get; } = new();

    /// <summary>Does the method body call a method with this name? Used for guards such as Url.IsLocalUrl.</summary>
    public bool Calls(string methodName) => _calledNames.Contains(methodName);

    /// <summary>Everything that is assigned to a local variable in this method.</summary>
    public IReadOnlyList<IOperation> ValuesOf(ISymbol variable) =>
        _assigned.TryGetValue(variable, out var values) ? values : Array.Empty<IOperation>();

    private void Collect(IOperation operation)
    {
        switch (operation)
        {
            case IVariableDeclaratorOperation declarator:
            {
                var initializer = declarator.Initializer
                                  ?? (declarator.Parent as IVariableDeclarationOperation)?.Initializer;
                if (initializer is not null) Flow(declarator.Symbol, initializer.Value);
                break;
            }
            case IAssignmentOperation assignment: // simple, compound (+=) and ??=
            {
                var target = TargetSymbol(assignment.Target);
                if (target is not null) Flow(target, assignment.Value);
                // order.Note = tainted  →  the object 'order' now carries tainted data
                if (assignment.Target is IMemberReferenceOperation { Instance: { } instance } && TargetSymbol(instance) is { } owner)
                    Flow(owner, assignment.Value);
                break;
            }
            case IForEachLoopOperation loop:
                foreach (var local in loop.Locals) Flow(local, loop.Collection);
                break;
            case IDeclarationPatternOperation { DeclaredSymbol: { } declared } pattern:
            {
                // if (value is string text)  /  switch (value) { case string text: ... }
                for (var parent = pattern.Parent; parent is not null; parent = parent.Parent)
                {
                    if (parent is IIsPatternOperation isPattern) { Flow(declared, isPattern.Value); break; }
                    if (parent is ISwitchOperation switchStatement) { Flow(declared, switchStatement.Value); break; }
                    if (parent is ISwitchExpressionOperation switchExpression) { Flow(declared, switchExpression.Value); break; }
                }
                break;
            }
            case IInvocationOperation invocation:
                CollectInvocation(invocation);
                break;
        }
    }

    private void CollectInvocation(IInvocationOperation invocation)
    {
        var method = invocation.TargetMethod;
        _calledNames.Add(method.Name);

        // Local functions share the variables of the method, so their parameters are just more variables
        if (method.MethodKind == MethodKind.LocalFunction)
        {
            foreach (var argument in invocation.Arguments)
                if (argument.Parameter is { } parameter) Flow(parameter, argument.Value);
        }

        var receiver = invocation.Instance
                       ?? (method.IsExtensionMethod && invocation.Arguments.Length > 0 ? invocation.Arguments[0].Value : null);

        if (receiver is not null)
        {
            foreach (var argument in invocation.Arguments)
            {
                // Request.Query.TryGetValue("q", out var value): the out variable receives what the receiver holds
                if (argument.Parameter?.RefKind == RefKind.Out && OutTarget(argument.Value) is { } outVariable)
                    Flow(outVariable, receiver);
            }

            // builder.Append(tainted), list.Add(tainted): the receiver now holds tainted data.
            // builder.Append("a").Append(tainted): the receiver is the start of the chain.
            var root = receiver;
            while (root.Unwrap() is IInvocationOperation { Instance: { } inner } chained && IsMutator(chained.TargetMethod)) root = inner;
            if (TargetSymbol(root) is { } receiverVariable && IsMutator(method))
            {
                foreach (var argument in invocation.Arguments)
                    if (!ReferenceEquals(argument.Value, receiver)) Flow(receiverVariable, argument.Value);
            }
        }

        // app.MapGet("/users", (string name, AppDb db) => ...): the lambda parameters are bound from the request
        if (IsEndpointMapping(method))
        {
            foreach (var argument in invocation.Arguments)
            {
                var value = argument.Value.Unwrap();
                if (value is IDelegateCreationOperation delegateCreation) value = delegateCreation.Target.Unwrap();
                switch (value)
                {
                    case IAnonymousFunctionOperation lambda:
                        foreach (var parameter in lambda.Symbol.Parameters)
                            if (EntryPoints.IsBound(parameter, minimalApi: true))
                                _variables[parameter] = TaintValue.FromRequest($"parameter '{parameter.Name}' of the {method.Name} handler");
                        break;
                    case IMethodReferenceOperation methodGroup:
                        EndpointMethodGroups.Add((methodGroup.Method, methodGroup.Syntax.GetLocation()));
                        break;
                }
            }
        }
    }

    private static bool IsEndpointMapping(IMethodSymbol method) =>
        method.Name.StartsWith("Map", StringComparison.Ordinal)
        && method.ContainingType?.Name is "EndpointRouteBuilderExtensions";

    private static bool IsMutator(IMethodSymbol method)
    {
        switch (method.Name)
        {
            case "Append":
            case "AppendLine":
            case "AppendFormat":
            case "AppendJoin":
            case "Insert":
            case "Add":
            case "AddRange":
            case "Enqueue":
            case "Push":
            case "TryAdd":
                return true;
            default:
                return false;
        }
    }

    private void Flow(ISymbol target, IOperation value)
    {
        _flows.Add((target, value));
        if (!_assigned.TryGetValue(target, out var values)) _assigned[target] = values = new List<IOperation>();
        values.Add(value);
    }

    private static ISymbol? TargetSymbol(IOperation? target)
    {
        switch (target?.Unwrap())
        {
            case ILocalReferenceOperation local: return local.Local;
            case IParameterReferenceOperation parameter: return parameter.Parameter;
            case IFieldReferenceOperation field when IsThisOrStatic(field.Instance): return field.Field;
            case IPropertyReferenceOperation property when IsThisOrStatic(property.Instance): return property.Property;
            default: return null;
        }
    }

    /// <summary>"Name" in "new Order { Name = x }" is a reference through the implicit receiver, not through "this".</summary>
    private static bool IsThisOrStatic(IOperation? instance) =>
        instance is null or IInstanceReferenceOperation { ReferenceKind: InstanceReferenceKind.ContainingTypeInstance };

    private static ISymbol? OutTarget(IOperation value)
    {
        switch (value.Unwrap())
        {
            case IDeclarationExpressionOperation declaration: return TargetSymbol(declaration.Expression);
            case var other: return TargetSymbol(other);
        }
    }

    // ------------------------------------------------------------------ the taint of an expression

    public TaintValue Of(IOperation? operation) => Of(operation, 0);

    private TaintValue Of(IOperation? operation, int depth)
    {
        if (operation is null || depth > 40) return TaintValue.None;
        if (operation.ConstantValue.HasValue) return TaintValue.None;
        if (operation.Type is { } type && !Carrier.CanCarry(type)) return TaintValue.None;

        switch (operation)
        {
            case IConversionOperation conversion: return Of(conversion.Operand, depth + 1);
            case IParenthesizedOperation parenthesized: return Of(parenthesized.Operand, depth + 1);
            case IAwaitOperation awaited: return Of(awaited.Operation, depth + 1);
            case IArgumentOperation argument: return Of(argument.Value, depth + 1);

            case ILocalReferenceOperation local: return Lookup(local.Local);
            case IParameterReferenceOperation parameter: return Lookup(parameter.Parameter);
            case IDeclarationExpressionOperation declaration: return Of(declaration.Expression, depth + 1);

            case IFieldReferenceOperation field:
                return Lookup(field.Field).Union(field.Instance is null or IInstanceReferenceOperation ? TaintValue.None : Of(field.Instance, depth + 1));

            case IPropertyReferenceOperation property:
                return OfProperty(property, depth);

            case IBinaryOperation binary:
                return Of(binary.LeftOperand, depth + 1).Union(Of(binary.RightOperand, depth + 1));

            case IInterpolatedStringOperation interpolated:
            {
                var result = TaintValue.None;
                foreach (var part in interpolated.Parts)
                    if (part is IInterpolationOperation interpolation) result = result.Union(Of(interpolation.Expression, depth + 1));
                return result;
            }

            case IConditionalOperation conditional:
                return Of(conditional.WhenTrue, depth + 1).Union(Of(conditional.WhenFalse, depth + 1));
            case ICoalesceOperation coalesce:
                return Of(coalesce.Value, depth + 1).Union(Of(coalesce.WhenNull, depth + 1));
            case IConditionalAccessOperation conditionalAccess:
                return Of(conditionalAccess.Operation, depth + 1).Union(Of(conditionalAccess.WhenNotNull, depth + 1));
            case IConditionalAccessInstanceOperation:
                return TaintValue.None; // the receiver was counted by the IConditionalAccessOperation above

            case ISwitchExpressionOperation switchExpression:
            {
                var result = TaintValue.None;
                foreach (var arm in switchExpression.Arms) result = result.Union(Of(arm.Value, depth + 1));
                return result;
            }

            case IArrayElementReferenceOperation element: return Of(element.ArrayReference, depth + 1);

            case IArrayCreationOperation arrayCreation:
            {
                var result = TaintValue.None;
                if (arrayCreation.Initializer is { } initializer)
                    foreach (var value in initializer.ElementValues) result = result.Union(Of(value, depth + 1));
                return result;
            }

            case IAnonymousObjectCreationOperation anonymous:
            {
                var result = TaintValue.None;
                foreach (var initializer in anonymous.Initializers)
                    result = result.Union(Of(initializer is IAssignmentOperation assignment ? assignment.Value : initializer, depth + 1));
                return result;
            }

            case IObjectCreationOperation creation:
            {
                var result = TaintValue.None;
                foreach (var argument in creation.Arguments) result = result.Union(Of(argument.Value, depth + 1));
                if (creation.Initializer is { } initializer)
                    foreach (var member in initializer.Initializers)
                        result = result.Union(Of(member is IAssignmentOperation assignment ? assignment.Value : member, depth + 1));
                return result;
            }

            case IInvocationOperation invocation:
                return OfInvocation(invocation, depth);

            default:
                return TaintValue.None;
        }
    }

    private TaintValue Lookup(ISymbol symbol) => _variables.TryGetValue(symbol, out var value) ? value : TaintValue.None;

    private TaintValue OfProperty(IPropertyReferenceOperation property, int depth)
    {
        var symbol = property.Property;

        // Request.Query, Request.Headers, Request.Form, Request.Cookies, Request.Path, Request.Body ...
        if (property.Instance?.Type is { } instanceType && instanceType.Is("Microsoft.AspNetCore.Http.HttpRequest"))
        {
            switch (symbol.Name)
            {
                case "Scheme": // "http" or "https"
                case "Method":
                case "Protocol":
                case "HttpContext":
                case "IsHttps":
                case "ContentLength":
                    return TaintValue.None;
                default:
                    return TaintValue.FromRequest("Request." + symbol.Name);
            }
        }

        if (EntryPoints.IsBoundProperty(symbol))
            return TaintValue.FromRequest($"bound property '{symbol.Name}'");

        var result = Lookup(symbol);
        if (property.Instance is not null and not IInstanceReferenceOperation)
            result = result.Union(Of(property.Instance, depth + 1));
        return result;
    }

    private TaintValue OfInvocation(IInvocationOperation invocation, int depth)
    {
        var method = invocation.TargetMethod;

        if (method.Name == "GetRouteValue" && method.ContainingType?.Name == "RoutingHttpContextExtensions")
            return TaintValue.FromRequest("a route value");

        var receiver = invocation.Instance;
        var firstIsReceiver = false;
        if (receiver is null && method.IsExtensionMethod && invocation.Arguments.Length > 0)
        {
            receiver = invocation.Arguments[0].Value;
            firstIsReceiver = true;
        }

        var result = receiver is null ? TaintValue.None : Of(receiver, depth + 1);

        // A call on a tainted object returns tainted data (text.Trim(), form["name"].ToString(), reader.ReadToEnd()).
        // Arguments only count when the result is text: db.Users.Where(u => u.Name == name) is a query, not the name.
        var returnType = method.ReturnType;
        if (Carrier.IsStringLike(returnType))
        {
            for (var i = firstIsReceiver ? 1 : 0; i < invocation.Arguments.Length; i++)
            {
                var value = invocation.Arguments[i].Value;
                if (value.Unwrap() is IAnonymousFunctionOperation or IDelegateCreationOperation) continue;
                result = result.Union(Of(value, depth + 1));
            }
        }

        var sanitizes = Sanitizers.For(method);
        return sanitizes == SinkKind.None ? result : result.Sanitized(sanitizes);
    }
}

/// <summary>Calls that make a value safe for some kinds of sinks.</summary>
internal static class Sanitizers
{
    private const SinkKind UrlEncoded = SinkKind.Ssrf | SinkKind.Xss | SinkKind.Redirect | SinkKind.Path;

    public static SinkKind For(IMethodSymbol method)
    {
        var type = method.ContainingType;
        if (type is null) return SinkKind.None;
        var name = method.Name;

        switch (type.Name)
        {
            case "Path" when type.Is("System.IO.Path"):
                return name is "GetFileName" or "GetFileNameWithoutExtension" or "GetExtension" ? SinkKind.Path : SinkKind.None;
            case "WebUtility" when type.Is("System.Net.WebUtility"):
            case "HttpUtility" when type.Is("System.Web.HttpUtility"):
                if (name is "HtmlEncode" or "HtmlAttributeEncode" or "JavaScriptStringEncode") return SinkKind.Xss;
                if (name is "UrlEncode" or "UrlPathEncode") return UrlEncoded;
                return SinkKind.None;
            case "Uri" when type.Is("System.Uri"):
                return name is "EscapeDataString" ? UrlEncoded : SinkKind.None;
            case "Regex" when type.Is("System.Text.RegularExpressions.Regex"):
                return name is "Escape" ? SinkKind.Regex : SinkKind.None;
            case "SecurityElement" when type.Is("System.Security.SecurityElement"):
                return name is "Escape" ? SinkKind.Xss : SinkKind.None;
        }

        if (name == "Encode" && type.InheritsFrom("System.Text.Encodings.Web.TextEncoder"))
            return type.InheritsFrom("System.Text.Encodings.Web.UrlEncoder") ? UrlEncoded : SinkKind.Xss;

        // The project's own helpers: EscapeLdapFilter(value), SanitizeFileName(value), HtmlEncode(value) ...
        // They are trusted for everything except SQL and commands, where only parameters and allow-lists are a real fix.
        if (method.DeclaringSyntaxReferences.Length > 0
            && (name.StartsWith("Escape", StringComparison.Ordinal) || name.StartsWith("Sanitize", StringComparison.Ordinal)
                || name.StartsWith("Encode", StringComparison.Ordinal) || name.StartsWith("HtmlEncode", StringComparison.Ordinal)))
            return SinkKind.Path | SinkKind.Redirect | SinkKind.Ssrf | SinkKind.Xss | SinkKind.Ldap | SinkKind.XPath | SinkKind.Regex;

        return SinkKind.None;
    }
}
