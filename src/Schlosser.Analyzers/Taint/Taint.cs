using System;
using Microsoft.CodeAnalysis;

namespace Schlosser.Taint;

/// <summary>The kinds of dangerous calls. A value can be made safe for some of them (HtmlEncode helps against XSS, not SQL).</summary>
[Flags]
internal enum SinkKind
{
    None = 0,
    Sql = 1,
    Command = 2,
    Path = 4,
    Redirect = 8,
    Ssrf = 16,
    Xss = 32,
    Ldap = 64,
    XPath = 128,
    Regex = 256,
}

/// <summary>
/// Where a value comes from. Two kinds of origin are tracked:
/// the HTTP request itself (<see cref="Request"/>), and the parameters of the method being analyzed (<see cref="Params"/>,
/// one bit per parameter). The second kind is what makes the analysis work across methods: a parameter that reaches
/// a dangerous call is remembered, and matched later with callers that pass request data into it.
/// </summary>
internal readonly struct TaintValue : IEquatable<TaintValue>
{
    public static readonly TaintValue None = default;

    public TaintValue(bool request, ulong parameters, SinkKind safeFor, string? source)
    {
        Request = request;
        Params = parameters;
        SafeFor = safeFor;
        Source = source;
    }

    public bool Request { get; }
    public ulong Params { get; }
    /// <summary>Sink kinds this value was sanitized for.</summary>
    public SinkKind SafeFor { get; }
    /// <summary>Human-readable origin of the request data, e.g. "parameter 'name' of UsersController.Search".</summary>
    public string? Source { get; }

    public bool IsNone => !Request && Params == 0;

    public static TaintValue FromRequest(string source) => new(true, 0, SinkKind.None, source);

    public static TaintValue FromParameter(int ordinal) => new(false, 1UL << ordinal, SinkKind.None, null);

    public TaintValue Union(TaintValue other)
    {
        if (other.IsNone) return this;
        if (IsNone) return other;
        // A mix of a sanitized and an unsanitized value is only as safe as its worst part
        return new TaintValue(Request || other.Request, Params | other.Params, SafeFor & other.SafeFor, Source ?? other.Source);
    }

    public TaintValue Sanitized(SinkKind kinds) => IsNone ? this : new TaintValue(Request, Params, SafeFor | kinds, Source);

    public bool Equals(TaintValue other) => Request == other.Request && Params == other.Params && SafeFor == other.SafeFor;
    public override bool Equals(object? obj) => obj is TaintValue other && Equals(other);
    public override int GetHashCode() => (Request ? 1 : 0) ^ Params.GetHashCode() ^ ((int)SafeFor << 8);
}

/// <summary>Which types can carry attacker-controlled text. An int parsed from the request cannot carry SQL.</summary>
internal static class Carrier
{
    public static bool CanCarry(ITypeSymbol? type)
    {
        if (type is null) return true;
        switch (type.SpecialType)
        {
            case SpecialType.System_Boolean:
            case SpecialType.System_Char:
            case SpecialType.System_SByte:
            case SpecialType.System_Byte:
            case SpecialType.System_Int16:
            case SpecialType.System_UInt16:
            case SpecialType.System_Int32:
            case SpecialType.System_UInt32:
            case SpecialType.System_Int64:
            case SpecialType.System_UInt64:
            case SpecialType.System_Single:
            case SpecialType.System_Double:
            case SpecialType.System_Decimal:
            case SpecialType.System_DateTime:
            case SpecialType.System_IntPtr:
            case SpecialType.System_UIntPtr:
            case SpecialType.System_Void:
                return false;
            case SpecialType.System_String:
            case SpecialType.System_Object:
                return true;
        }

        if (type.TypeKind == TypeKind.Enum) return false;
        if (type is IArrayTypeSymbol array) return CanCarry(array.ElementType);

        if (type is INamedTypeSymbol named)
        {
            var ns = named.ContainingNamespace?.ToDisplayString() ?? "";
            if (ns == "System")
            {
                switch (named.Name)
                {
                    case "Guid":
                    case "DateTimeOffset":
                    case "TimeSpan":
                    case "DateOnly":
                    case "TimeOnly":
                    case "Int128":
                    case "UInt128":
                    case "Half":
                    case "Type":
                    case "Version":
                        return false;
                    case "Nullable":
                        return CanCarry(named.TypeArguments[0]);
                }
            }

            if (ns == "System.Threading" && named.Name == "CancellationToken") return false;
            if (ns == "System.Numerics" && named.Name == "BigInteger") return false;
            if (ns == "System.Net" && named.Name == "IPAddress") return false;

            // Task<int>, List<Guid>, Dictionary<int, long>: only as dangerous as what is inside
            if (named.IsGenericType && (ns.StartsWith("System.Collections", StringComparison.Ordinal) || ns == "System.Threading.Tasks"))
            {
                foreach (var argument in named.TypeArguments)
                    if (CanCarry(argument)) return true;
                return false;
            }
        }

        return true;
    }

    /// <summary>Types that are text or wrap text. Unknown methods only pass taint on when they return one of these.</summary>
    public static bool IsStringLike(ITypeSymbol? type)
    {
        if (type is null) return false;
        if (type.SpecialType is SpecialType.System_String or SpecialType.System_Object) return true;
        if (type is IArrayTypeSymbol array) return IsStringLike(array.ElementType);
        if (type is not INamedTypeSymbol named) return false;

        switch (named.Name)
        {
            case "StringValues":
            case "Uri":
            case "UriBuilder":
            case "StringBuilder":
            case "PathString":
            case "QueryString":
            case "HostString":
            case "HtmlString":
            case "FormattableString":
                return true;
        }

        if (named.IsGenericType)
        {
            var ns = named.ContainingNamespace?.ToDisplayString() ?? "";
            if (ns.StartsWith("System.Collections", StringComparison.Ordinal) || ns == "System.Threading.Tasks" || ns == "System")
            {
                foreach (var argument in named.TypeArguments)
                    if (argument.SpecialType != SpecialType.System_Object && IsStringLike(argument)) return true;
            }
        }

        return false;
    }
}
