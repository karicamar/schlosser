using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;
using Schlosser.Taint;

namespace Schlosser;

/// <summary>
/// SL001 to SL010: follows request data to dangerous calls.
///
/// Inside one method the result is reported immediately. Across methods it works with summaries:
/// while a method is analyzed, every parameter that reaches a dangerous call is recorded, and so is every call
/// that passes request data or a parameter on. When the whole compilation has been seen, the two lists are joined:
/// request data → call → parameter → ... → dangerous call. Interface and virtual calls are resolved to the
/// implementations in the same compilation, so Controller → IUserRepository → SqlUserRepository is followed.
/// </summary>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class InjectionAnalyzer : DiagnosticAnalyzer
{
    private const int MaxCallDepth = 8;

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } = ImmutableArray.Create(
        Rules.SqlInjection, Rules.SqlBuiltFromStrings, Rules.CommandInjection, Rules.PathTraversal, Rules.OpenRedirect,
        Rules.Ssrf, Rules.Xss, Rules.LdapInjection, Rules.XPathInjection, Rules.RegexInjection);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterCompilationStartAction(start =>
        {
            var state = new State();
            start.RegisterOperationBlockAction(state.AnalyzeBlock);
            start.RegisterCompilationEndAction(state.Finish);
        });
    }

    internal static DiagnosticDescriptor RuleFor(SinkKind kind) => kind switch
    {
        SinkKind.Sql => Rules.SqlInjection,
        SinkKind.Command => Rules.CommandInjection,
        SinkKind.Path => Rules.PathTraversal,
        SinkKind.Redirect => Rules.OpenRedirect,
        SinkKind.Ssrf => Rules.Ssrf,
        SinkKind.Xss => Rules.Xss,
        SinkKind.Ldap => Rules.LdapInjection,
        SinkKind.XPath => Rules.XPathInjection,
        _ => Rules.RegexInjection,
    };

    /// <summary>A parameter of a method: the unit the cross-method analysis works with.</summary>
    private readonly struct ParameterKey : IEquatable<ParameterKey>
    {
        public ParameterKey(IMethodSymbol method, int ordinal)
        {
            Method = method.OriginalDefinition;
            Ordinal = ordinal;
        }

        public IMethodSymbol Method { get; }
        public int Ordinal { get; }

        public bool Equals(ParameterKey other) =>
            Ordinal == other.Ordinal && SymbolEqualityComparer.Default.Equals(Method, other.Method);

        public override bool Equals(object? obj) => obj is ParameterKey other && Equals(other);
        public override int GetHashCode() => SymbolEqualityComparer.Default.GetHashCode(Method) * 31 + Ordinal;
    }

    private sealed class SinkHit
    {
        public SinkHit(SinkKind kind, Location location, string name)
        {
            Kind = kind;
            Location = location;
            Name = name;
        }

        public SinkKind Kind { get; }
        public Location Location { get; }
        public string Name { get; }
    }

    private sealed class Edge
    {
        public Edge(ParameterKey target, SinkKind safeFor)
        {
            Target = target;
            SafeFor = safeFor;
        }

        public ParameterKey Target { get; }
        public SinkKind SafeFor { get; }
    }

    private sealed class Root
    {
        public Root(ParameterKey target, SinkKind safeFor, string source, string caller, Location location)
        {
            Target = target;
            SafeFor = safeFor;
            Source = source;
            Caller = caller;
            Location = location;
        }

        public ParameterKey Target { get; }
        public SinkKind SafeFor { get; }
        public string Source { get; }
        public string Caller { get; }
        public Location Location { get; }
    }

    private sealed class SqlCandidate
    {
        public SqlCandidate(Location location, string sink, string part)
        {
            Location = location;
            Sink = sink;
            Part = part;
        }

        public Location Location { get; }
        public string Sink { get; }
        public string Part { get; }
    }

    private sealed class State
    {
        private readonly ConcurrentDictionary<ParameterKey, ConcurrentBag<SinkHit>> _sinks = new();
        private readonly ConcurrentDictionary<ParameterKey, ConcurrentBag<Edge>> _edges = new();
        private readonly ConcurrentBag<Root> _roots = new();
        private readonly ConcurrentBag<SqlCandidate> _sqlCandidates = new();
        private readonly ConcurrentDictionary<Location, bool> _reported = new();
        // interface or base method → implementations and overrides in this compilation
        private readonly ConcurrentDictionary<ISymbol, ConcurrentBag<IMethodSymbol>> _implementations = new(SymbolEqualityComparer.Default);

        public void AnalyzeBlock(OperationBlockAnalysisContext context)
        {
            var taint = new MethodTaint(context.OwningSymbol, context.OperationBlocks);
            var method = taint.Method;
            if (method is not null) RecordImplementations(method);

            foreach (var (handler, location) in taint.EndpointMethodGroups)
            {
                foreach (var parameter in handler.Parameters)
                    if (EntryPoints.IsBound(parameter, minimalApi: true))
                        _roots.Add(new Root(new ParameterKey(handler, parameter.Ordinal), SinkKind.None,
                            $"parameter '{parameter.Name}' of the endpoint handler {handler.Short()}", "endpoint mapping", location));
            }

            var found = new List<SinkUse>();
            foreach (var block in context.OperationBlocks)
            {
                foreach (var operation in block.DescendantsAndSelf())
                {
                    found.Clear();
                    Sinks.Find(operation, found);
                    foreach (var sink in found) CheckSink(context, taint, sink);

                    switch (operation)
                    {
                        case IInvocationOperation invocation:
                            RecordCall(taint, invocation.TargetMethod, invocation.Arguments, invocation.Syntax.GetLocation());
                            break;
                        case IObjectCreationOperation { Constructor: { } constructor } creation:
                            RecordCall(taint, constructor, creation.Arguments, creation.Syntax.GetLocation());
                            break;
                    }
                }
            }
        }

        private void CheckSink(OperationBlockAnalysisContext context, MethodTaint taint, SinkUse sink)
        {
            var value = taint.Of(sink.Value);
            var location = sink.Value.Syntax.GetLocation();

            var safe = (value.SafeFor & sink.Kind) != 0 || IsGuarded(taint, sink.Kind)
                       || (sink.Kind == SinkKind.Ssrf && HostIsFixed(taint, sink.Value, 0));

            if (!value.IsNone && !safe)
            {
                if (value.Request)
                {
                    if (_reported.TryAdd(location, true))
                        context.ReportDiagnostic(Diagnostic.Create(RuleFor(sink.Kind), location, value.Source ?? "request data", sink.Name, ""));
                }

                if (value.Params != 0 && taint.Method is { } method)
                {
                    for (var ordinal = 0; ordinal < method.Parameters.Length && ordinal < 64; ordinal++)
                    {
                        if ((value.Params & (1UL << ordinal)) == 0) continue;
                        _sinks.GetOrAdd(new ParameterKey(method, ordinal), _ => new ConcurrentBag<SinkHit>())
                            .Add(new SinkHit(sink.Kind, location, sink.Name));
                    }
                }
            }

            if (sink.Kind == SinkKind.Sql && !value.Request
                && DynamicPart(taint, sink.Value, new HashSet<ISymbol>(SymbolEqualityComparer.Default)) is { } part)
            {
                _sqlCandidates.Add(new SqlCandidate(location, sink.Name, part));
            }
        }

        /// <summary>Checks elsewhere in the method that make the sink safe. Coarse on purpose: a check anywhere counts.</summary>
        private static bool IsGuarded(MethodTaint taint, SinkKind kind) => kind switch
        {
            SinkKind.Redirect => taint.Calls("IsLocalUrl"),
            SinkKind.Path => taint.Calls("GetFullPath") && (taint.Calls("StartsWith") || taint.Calls("IsSubPathOf") || taint.Calls("GetRelativePath")),
            _ => false,
        };

        private void RecordCall(MethodTaint taint, IMethodSymbol target, ImmutableArray<IArgumentOperation> arguments, Location location)
        {
            if (arguments.IsEmpty) return;
            if (target.MethodKind is MethodKind.LocalFunction or MethodKind.AnonymousFunction or MethodKind.DelegateInvoke) return;
            target = target.OriginalDefinition;
            // Only code of this compilation has a summary. Interface methods declared here are resolved to implementations later.
            if (target.DeclaringSyntaxReferences.IsEmpty) return;

            foreach (var argument in arguments)
            {
                if (argument.Parameter is not { } parameter) continue;
                var value = taint.Of(argument.Value);
                if (value.IsNone) continue;

                var key = new ParameterKey(target, parameter.Ordinal);
                if (value.Request)
                    _roots.Add(new Root(key, value.SafeFor, value.Source ?? "request data", taint.Method?.Short() ?? "top-level code", location));

                if (value.Params != 0 && taint.Method is { } caller)
                {
                    for (var ordinal = 0; ordinal < caller.Parameters.Length && ordinal < 64; ordinal++)
                    {
                        if ((value.Params & (1UL << ordinal)) == 0) continue;
                        _edges.GetOrAdd(new ParameterKey(caller, ordinal), _ => new ConcurrentBag<Edge>())
                            .Add(new Edge(key, value.SafeFor));
                    }
                }
            }
        }

        private void RecordImplementations(IMethodSymbol method)
        {
            if (method.MethodKind is not (MethodKind.Ordinary or MethodKind.ExplicitInterfaceImplementation)) return;

            for (var overridden = method.OverriddenMethod; overridden is not null; overridden = overridden.OverriddenMethod)
                _implementations.GetOrAdd(overridden.OriginalDefinition, _ => new ConcurrentBag<IMethodSymbol>()).Add(method);

            foreach (var explicitImplementation in method.ExplicitInterfaceImplementations)
                _implementations.GetOrAdd(explicitImplementation.OriginalDefinition, _ => new ConcurrentBag<IMethodSymbol>()).Add(method);

            var type = method.ContainingType;
            if (type is null || method.DeclaredAccessibility != Accessibility.Public) return;
            foreach (var contract in type.AllInterfaces)
            {
                foreach (var member in contract.GetMembers(method.Name))
                {
                    if (SymbolEqualityComparer.Default.Equals(type.FindImplementationForInterfaceMember(member), method))
                        _implementations.GetOrAdd(member.OriginalDefinition, _ => new ConcurrentBag<IMethodSymbol>()).Add(method);
                }
            }
        }

        // ------------------------------------------------------------------ joining the summaries

        public void Finish(CompilationAnalysisContext context)
        {
            // Stable order, so that the message (which names the first path found) does not change between builds
            var roots = _roots.OrderBy(r => r.Location.SourceTree?.FilePath, StringComparer.Ordinal)
                .ThenBy(r => r.Location.SourceSpan.Start).ToList();

            foreach (var root in roots)
            {
                var visited = new HashSet<(ParameterKey, SinkKind)>();
                var queue = new Queue<(ParameterKey Key, SinkKind SafeFor, string Path, int Depth)>();
                queue.Enqueue((root.Target, root.SafeFor, root.Caller, 1));

                while (queue.Count > 0)
                {
                    var (key, safeFor, path, depth) = queue.Dequeue();
                    foreach (var method in Targets(key.Method))
                    {
                        var current = new ParameterKey(method, key.Ordinal);
                        if (!visited.Add((current, safeFor))) continue;
                        var currentPath = path + " → " + method.Short();

                        if (_sinks.TryGetValue(current, out var hits))
                        {
                            foreach (var hit in hits.OrderBy(h => h.Location.SourceSpan.Start))
                            {
                                if ((hit.Kind & safeFor) != 0) continue;
                                if (!_reported.TryAdd(hit.Location, true)) continue;
                                context.ReportDiagnostic(Diagnostic.Create(RuleFor(hit.Kind), hit.Location,
                                    additionalLocations: new[] { root.Location },
                                    root.Source, hit.Name, " (call path: " + currentPath + ")"));
                            }
                        }

                        if (depth >= MaxCallDepth || !_edges.TryGetValue(current, out var edges)) continue;
                        foreach (var edge in edges)
                            queue.Enqueue((edge.Target, safeFor | edge.SafeFor, currentPath, depth + 1));
                    }
                }
            }

            foreach (var candidate in _sqlCandidates.OrderBy(c => c.Location.SourceSpan.Start))
            {
                if (_reported.TryAdd(candidate.Location, true))
                    context.ReportDiagnostic(Diagnostic.Create(Rules.SqlBuiltFromStrings, candidate.Location, candidate.Sink, candidate.Part));
            }
        }

        private IEnumerable<IMethodSymbol> Targets(IMethodSymbol method)
        {
            yield return method;
            if (_implementations.TryGetValue(method, out var implementations))
                foreach (var implementation in implementations.Distinct<IMethodSymbol>(SymbolEqualityComparer.Default))
                    yield return implementation.OriginalDefinition;
        }
    }

    // ------------------------------------------------------------------ SL002: SQL text built from strings

    /// <summary>The first non-constant piece of text in a SQL string, or null if the string is constant or passed through as is.</summary>
    private static string? DynamicPart(MethodTaint taint, IOperation operation, HashSet<ISymbol> seen)
    {
        operation = operation.Unwrap();
        if (operation.ConstantValue.HasValue) return null;

        switch (operation)
        {
            case IInterpolatedStringOperation interpolated:
                foreach (var part in interpolated.Parts)
                    if (part is IInterpolationOperation interpolation && Piece(taint, interpolation.Expression, seen) is { } found)
                        return found;
                return null;

            case IBinaryOperation { OperatorKind: BinaryOperatorKind.Add } binary:
                return Piece(taint, binary.LeftOperand, seen) ?? Piece(taint, binary.RightOperand, seen);

            case ICompoundAssignmentOperation compound:
                return Piece(taint, compound.Value, seen);

            case IInvocationOperation invocation:
            {
                var method = invocation.TargetMethod;
                if (method.ContainingType?.SpecialType == SpecialType.System_String && method.Name is "Format" or "Concat" or "Join")
                {
                    foreach (var argument in invocation.Arguments)
                    {
                        if (argument.Parameter?.Name is "format" or "separator") continue;
                        if (Piece(taint, argument.Value, seen) is { } found) return found;
                    }
                }
                else if (method.Name == "ToString" && invocation.Instance?.Unwrap() is ILocalReferenceOperation builder
                         && builder.Type?.Name == "StringBuilder")
                {
                    foreach (var appended in taint.ValuesOf(builder.Local))
                        if (Piece(taint, appended, seen) is { } found) return found;
                }

                return null;
            }

            case ILocalReferenceOperation local:
                if (!seen.Add(local.Local)) return null;
                foreach (var value in taint.ValuesOf(local.Local))
                {
                    // sql += " AND name = '" + name + "'" is recorded as the value added
                    var assignedByCompound = value.Parent is ICompoundAssignmentOperation;
                    var found = assignedByCompound ? Piece(taint, value, seen) : DynamicPart(taint, value, seen);
                    if (found is not null) return found;
                }
                return null;

            default:
                return null;
        }
    }

    /// <summary>One operand of a concatenation: constant and non-text pieces are fine, nested concatenations are searched.</summary>
    private static string? Piece(MethodTaint taint, IOperation operation, HashSet<ISymbol> seen)
    {
        operation = operation.Unwrap();
        if (operation.ConstantValue.HasValue) return null;
        if (operation is IArrayCreationOperation { Initializer: { } initializer }) // params object[] of string.Format
        {
            foreach (var element in initializer.ElementValues)
                if (Piece(taint, element, seen) is { } found) return found;
            return null;
        }

        if (!Carrier.CanCarry(operation.Type)) return null;
        if (operation is INameOfOperation or ITypeOfOperation) return null;
        if (operation is IFieldReferenceOperation { Field: { IsStatic: true, IsReadOnly: true } }) return null;
        if (operation is IInterpolatedStringOperation or IBinaryOperation) return DynamicPart(taint, operation, seen);
        if (operation is ILocalReferenceOperation local && taint.ValuesOf(local.Local).Count > 0)
        {
            var nested = DynamicPart(taint, operation, seen);
            if (nested is not null) return nested;
        }

        if (IsChoiceOfConstants(taint, operation, 0)) return null;

        var name = Symbols.NameOf(operation);
        return name is null ? "an expression" : "'" + name + "'";
    }

    /// <summary>
    /// sort == "city" ? "City" : "Name" can only ever be one of the constants, whatever the request says.
    /// This is the allow-list pattern that is the correct fix for ORDER BY columns and table names.
    /// </summary>
    private static bool IsChoiceOfConstants(MethodTaint taint, IOperation operation, int depth)
    {
        operation = operation.Unwrap();
        if (operation.ConstantValue.HasValue) return true;
        if (depth > 6) return false;

        switch (operation)
        {
            case IConditionalOperation conditional:
                return conditional.WhenFalse is not null
                       && IsChoiceOfConstants(taint, conditional.WhenTrue, depth + 1)
                       && IsChoiceOfConstants(taint, conditional.WhenFalse, depth + 1);
            case ISwitchExpressionOperation switchExpression:
                foreach (var arm in switchExpression.Arms)
                    if (arm.Value.Unwrap() is not IThrowOperation && !IsChoiceOfConstants(taint, arm.Value, depth + 1)) return false;
                return true;
            case ICoalesceOperation coalesce:
                return IsChoiceOfConstants(taint, coalesce.Value, depth + 1) && IsChoiceOfConstants(taint, coalesce.WhenNull, depth + 1);
            case IFieldReferenceOperation { Field: { IsStatic: true, IsReadOnly: true } }:
            case INameOfOperation:
                return true;
            case ILocalReferenceOperation local:
            {
                var values = taint.ValuesOf(local.Local);
                if (values.Count == 0) return false;
                foreach (var value in values)
                    if (value.Parent is ICompoundAssignmentOperation || !IsChoiceOfConstants(taint, value, depth + 1)) return false;
                return true;
            }
            default:
                return false;
        }
    }

    // ------------------------------------------------------------------ SL006: is the host of the URL fixed?

    private static readonly Regex AbsoluteWithHost = new(@"^[a-z][a-z0-9+.-]*://[^/?#]+[/?#]", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    /// <summary>
    /// "https://api.example.com/users/" + id cannot reach another host, and neither can a relative address
    /// (the HttpClient's BaseAddress decides). Only a request-controlled scheme or host is server-side request forgery.
    /// </summary>
    private static bool HostIsFixed(MethodTaint taint, IOperation operation, int depth)
    {
        if (depth > 6) return false;
        operation = operation.Unwrap();

        switch (operation)
        {
            case IObjectCreationOperation { Arguments.Length: > 0 } creation when creation.Type?.Name is "Uri" or "UriBuilder":
                // new Uri(baseUri, relative): the base decides the host as long as the relative part cannot be absolute,
                // which it can ("//evil.example"), so only a single-argument Uri is looked into
                return creation.Arguments.Length == 1 && HostIsFixed(taint, creation.Arguments[0].Value, depth + 1);

            case ILocalReferenceOperation local:
            {
                var values = taint.ValuesOf(local.Local);
                if (values.Count == 0) return false;
                foreach (var value in values)
                    if (!HostIsFixed(taint, value, depth + 1)) return false;
                return true;
            }
        }

        var parts = new List<IOperation>();
        Flatten(operation, parts);
        if (parts.Count < 2) return false;

        var first = parts[0];
        if (first.ConstantValue is { HasValue: true, Value: string })
        {
            // leading constant text, possibly continued by further constants
            var prefix = "";
            foreach (var part in parts)
            {
                if (part.ConstantValue is { HasValue: true, Value: string text }) prefix += text;
                else break;
            }

            if (AbsoluteWithHost.IsMatch(prefix)) return true;
            // relative address: no scheme and not protocol-relative
            return prefix.Length > 0 && prefix.IndexOf("://", StringComparison.Ordinal) < 0
                   && !prefix.StartsWith("//", StringComparison.Ordinal) && !prefix.StartsWith("\\", StringComparison.Ordinal);
        }

        // $"{_options.BaseUrl}/users/{id}": an untainted base followed by a slash
        return taint.Of(first).IsNone
               && parts[1].ConstantValue is { HasValue: true, Value: string next }
               && (next.StartsWith("/", StringComparison.Ordinal) || next.StartsWith("?", StringComparison.Ordinal));
    }

    private static void Flatten(IOperation operation, List<IOperation> parts)
    {
        operation = operation.Unwrap();
        switch (operation)
        {
            case IBinaryOperation { OperatorKind: BinaryOperatorKind.Add } binary when !operation.ConstantValue.HasValue:
                Flatten(binary.LeftOperand, parts);
                Flatten(binary.RightOperand, parts);
                break;
            case IInterpolatedStringOperation interpolated when !operation.ConstantValue.HasValue:
                foreach (var part in interpolated.Parts)
                {
                    if (part is IInterpolatedStringTextOperation text) parts.Add(text.Text);
                    else if (part is IInterpolationOperation interpolation) parts.Add(interpolation.Expression.Unwrap());
                }
                break;
            default:
                parts.Add(operation);
                break;
        }
    }
}
