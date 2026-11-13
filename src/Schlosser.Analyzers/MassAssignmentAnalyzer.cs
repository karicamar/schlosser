using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Schlosser.Taint;

namespace Schlosser;

/// <summary>
/// SL011: a controller action, page handler or minimal API handler takes a database entity as its parameter.
/// Model binding then fills every property the client sends (over-posting): IsAdmin, Role, Balance, OwnerId.
/// Entities are found through the DbSet properties of the DbContext classes in the compilation.
/// </summary>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class MassAssignmentAnalyzer : DiagnosticAnalyzer
{
    private static readonly string[] SensitiveWords =
    {
        "admin", "role", "roles", "permission", "permissions", "balance", "owner", "tenant", "password", "hash", "verified", "confirmed",
        "approved", "status", "price", "credit", "credits", "locked", "active", "enabled", "deleted", "salary", "limit",
    };

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } = ImmutableArray.Create(Rules.MassAssignment);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterCompilationStartAction(start =>
        {
            var entities = new ConcurrentDictionary<ITypeSymbol, bool>(SymbolEqualityComparer.Default);
            var candidates = new ConcurrentBag<(IParameterSymbol Parameter, INamedTypeSymbol Type, string Handler)>();

            start.RegisterSymbolAction(symbol =>
            {
                var type = (INamedTypeSymbol)symbol.Symbol;
                if (!type.InheritsFrom("Microsoft.EntityFrameworkCore.DbContext")) return;
                foreach (var member in type.GetMembers())
                {
                    if (member is IPropertySymbol { Type: INamedTypeSymbol { Name: "DbSet", TypeArguments.Length: 1 } set })
                        entities.TryAdd(set.TypeArguments[0], true);
                }
            }, SymbolKind.NamedType);

            start.RegisterSymbolAction(symbol =>
            {
                var method = (IMethodSymbol)symbol.Symbol;
                if (!EntryPoints.IsEntryPoint(method)) return;
                foreach (var parameter in method.Parameters) Consider(parameter, method.Short(), candidates);
            }, SymbolKind.Method);

            // Minimal API handlers: lambdas and method groups passed to MapPost, MapPut ...
            start.RegisterOperationAction(operation =>
            {
                var invocation = (Microsoft.CodeAnalysis.Operations.IInvocationOperation)operation.Operation;
                var target = invocation.TargetMethod;
                if (!target.Name.StartsWith("Map", StringComparison.Ordinal) || target.ContainingType?.Name != "EndpointRouteBuilderExtensions") return;
                foreach (var argument in invocation.Arguments)
                {
                    var value = argument.Value.Unwrap();
                    if (value is Microsoft.CodeAnalysis.Operations.IDelegateCreationOperation creation) value = creation.Target.Unwrap();
                    var handler = value switch
                    {
                        Microsoft.CodeAnalysis.Operations.IAnonymousFunctionOperation lambda => lambda.Symbol,
                        Microsoft.CodeAnalysis.Operations.IMethodReferenceOperation reference => reference.Method,
                        _ => null,
                    };
                    if (handler is null) continue;
                    foreach (var parameter in handler.Parameters) Consider(parameter, "the " + target.Name + " handler", candidates);
                }
            }, OperationKind.Invocation);

            start.RegisterCompilationEndAction(end =>
            {
                foreach (var (parameter, type, handler) in candidates.OrderBy(c => c.Parameter.Locations.FirstOrDefault()?.SourceSpan.Start ?? 0))
                {
                    if (!entities.ContainsKey(type)) continue;
                    var location = parameter.Locations.FirstOrDefault();
                    if (location is null || !location.IsInSource) continue;
                    end.ReportDiagnostic(Diagnostic.Create(Rules.MassAssignment, location, handler, type.Name, Examples(type)));
                }
            });
        });
    }

    private static void Consider(IParameterSymbol parameter, string handler,
        ConcurrentBag<(IParameterSymbol, INamedTypeSymbol, string)> candidates)
    {
        if (parameter.HasAttribute("FromServices", "FromKeyedServices")) return;
        // [Bind("Title,Text")] is an explicit allow-list
        if (parameter.HasAttribute("Bind")) return;
        if (parameter.Type is INamedTypeSymbol { TypeKind: TypeKind.Class } type && type.DeclaringSyntaxReferences.Length > 0)
            candidates.Add((parameter, type, handler));
    }

    /// <summary>The properties an attacker would set first, for the message.</summary>
    private static string Examples(INamedTypeSymbol type)
    {
        var properties = new List<string>();
        for (var current = type; current is not null && current.SpecialType != SpecialType.System_Object; current = current.BaseType)
            foreach (var member in current.GetMembers())
                if (member is IPropertySymbol { DeclaredAccessibility: Accessibility.Public, SetMethod.DeclaredAccessibility: Accessibility.Public, IsStatic: false } property)
                    properties.Add(property.Name);

        var sensitive = properties.Where(p => Names.Words(p).Any(w => Array.IndexOf(SensitiveWords, w) >= 0)).Take(3).ToList();
        if (sensitive.Count == 0) sensitive = properties.Where(p => p.EndsWith("Id", StringComparison.Ordinal)).Take(2).ToList();
        if (sensitive.Count == 0) sensitive = properties.Take(2).ToList();
        return sensitive.Count == 0 ? "its key" : string.Join(", ", sensitive.Select(p => "'" + p + "'"));
    }
}
