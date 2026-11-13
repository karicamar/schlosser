using System;
using System.Collections.Generic;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Operations;

namespace Schlosser;

/// <summary>
/// Type checks by full name. The analyzers never reference ASP.NET Core, EF Core or Dapper themselves,
/// so they also work in projects that use only some of those libraries.
/// </summary>
internal static class Symbols
{
    /// <summary>Namespace-qualified metadata name, e.g. "System.Data.Common.DbCommand".</summary>
    public static string FullName(this ITypeSymbol? type)
    {
        if (type is null) return "";
        if (type is IArrayTypeSymbol array) return array.ElementType.FullName() + "[]";
        var definition = type.OriginalDefinition;
        var ns = definition.ContainingNamespace;
        var name = definition.ContainingType is { } outer ? outer.FullName() + "+" + definition.Name : definition.Name;
        return ns is null || ns.IsGlobalNamespace || definition.ContainingType is not null
            ? name
            : ns.ToDisplayString() + "." + name;
    }

    public static bool Is(this ITypeSymbol? type, string fullName)
    {
        if (type is null) return false;
        // cheap check first: the simple name is the part after the last dot
        var dot = fullName.LastIndexOf('.');
        var simple = dot < 0 ? fullName : fullName.Substring(dot + 1);
        return type.Name == simple && type.FullName() == fullName;
    }

    public static bool IsAny(this ITypeSymbol? type, params string[] fullNames)
    {
        foreach (var name in fullNames)
            if (type.Is(name)) return true;
        return false;
    }

    /// <summary>The type itself or one of its base classes has this full name.</summary>
    public static bool InheritsFrom(this ITypeSymbol? type, string fullName)
    {
        for (var current = type; current is not null; current = current.BaseType)
            if (current.Is(fullName)) return true;
        return false;
    }

    /// <summary>The type is, inherits from or implements a type with this full name.</summary>
    public static bool IsOrImplements(this ITypeSymbol? type, string fullName)
    {
        if (type is null) return false;
        if (type.InheritsFrom(fullName)) return true;
        foreach (var contract in type.AllInterfaces)
            if (contract.Is(fullName)) return true;
        return false;
    }

    public static bool HasAttribute(this ISymbol symbol, params string[] attributeNames)
    {
        foreach (var attribute in symbol.GetAttributes())
        {
            var name = attribute.AttributeClass?.Name;
            if (name is null) continue;
            foreach (var wanted in attributeNames)
                if (name == wanted || name == wanted + "Attribute") return true;
        }
        return false;
    }

    public static IOperation Unwrap(this IOperation operation)
    {
        while (true)
        {
            switch (operation)
            {
                case IConversionOperation conversion: operation = conversion.Operand; continue;
                case IParenthesizedOperation parenthesized: operation = parenthesized.Operand; continue;
                case IAwaitOperation awaited: operation = awaited.Operation; continue;
                default: return operation;
            }
        }
    }

    /// <summary>"Type.Member" for messages.</summary>
    public static string Short(this ISymbol symbol)
    {
        if (symbol is IMethodSymbol { MethodKind: MethodKind.Constructor } constructor)
            return "new " + constructor.ContainingType.Name;
        return symbol.ContainingType is { } type ? type.Name + "." + symbol.Name : symbol.Name;
    }

    public static IEnumerable<IOperation> DescendantsAndSelf(this IOperation root)
    {
        var stack = new Stack<IOperation>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            var current = stack.Pop();
            yield return current;
            foreach (var child in current.ChildOperations) stack.Push(child);
        }
    }

    public static bool ContainsWord(string name, string[] words)
    {
        foreach (var word in words)
            if (name.IndexOf(word, StringComparison.OrdinalIgnoreCase) >= 0) return true;
        return false;
    }

    /// <summary>The name behind an expression: local, parameter, field or property name; for calls the method name.</summary>
    public static string? NameOf(IOperation? operation)
    {
        switch (operation?.Unwrap())
        {
            case ILocalReferenceOperation local: return local.Local.Name;
            case IParameterReferenceOperation parameter: return parameter.Parameter.Name;
            case IMemberReferenceOperation member: return member.Member.Name;
            case IInvocationOperation invocation: return invocation.TargetMethod.Name;
            default: return null;
        }
    }
}
