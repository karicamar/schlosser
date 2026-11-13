using System;
using Microsoft.CodeAnalysis;

namespace Schlosser.Taint;

/// <summary>Where request data enters the program: controller actions, Razor Page handlers, SignalR hub methods, minimal API handlers.</summary>
internal static class EntryPoints
{
    private static readonly string[] BindingAttributes =
        { "FromBody", "FromQuery", "FromRoute", "FromForm", "FromHeader", "AsParameters", "BindProperty", "SupplyParameterFromQuery", "SupplyParameterFromForm" };

    private static readonly string[] ServiceSuffixes =
        { "Service", "Repository", "Context", "Client", "Manager", "Handler", "Store", "Factory", "Provider", "Options", "Logger", "Accessor", "Sender", "Validator" };

    public static bool IsEntryPoint(IMethodSymbol method)
    {
        if (method.MethodKind != MethodKind.Ordinary || method.DeclaredAccessibility != Accessibility.Public || method.IsStatic)
            return false;
        if (method.HasAttribute("NonAction")) return false;

        var type = method.ContainingType;
        if (type is null) return false;
        if (IsController(type)) return true;
        if (type.InheritsFrom("Microsoft.AspNetCore.Mvc.RazorPages.PageModel"))
            return method.Name.StartsWith("On", StringComparison.Ordinal);
        if (type.InheritsFrom("Microsoft.AspNetCore.SignalR.Hub")) return true;
        return false;
    }

    public static bool IsController(INamedTypeSymbol type)
    {
        if (type.InheritsFrom("Microsoft.AspNetCore.Mvc.ControllerBase")) return true;
        for (var current = type; current is not null; current = current.BaseType)
            if (current.HasAttribute("ApiController", "Controller")) return true;
        return false;
    }

    /// <summary>Is this parameter filled from the request (and able to carry text)?</summary>
    public static bool IsBound(IParameterSymbol parameter, bool minimalApi)
    {
        if (parameter.HasAttribute("FromServices", "FromKeyedServices")) return false;
        var type = parameter.Type;
        if (!Carrier.CanCarry(type)) return false;
        if (parameter.HasAttribute(BindingAttributes)) return true;
        return IsRequestModel(type, minimalApi);
    }

    /// <summary>A property that model binding fills: [BindProperty], [FromQuery] ... or a class with [BindProperties].</summary>
    public static bool IsBoundProperty(IPropertySymbol property)
    {
        if (property.HasAttribute(BindingAttributes)) return true;
        return property.ContainingType is { } type
               && type.HasAttribute("BindProperties")
               && property.DeclaredAccessibility == Accessibility.Public
               && property.SetMethod is not null;
    }

    private static bool IsRequestModel(ITypeSymbol type, bool minimalApi)
    {
        if (Carrier.IsStringLike(type)) return true;
        if (type is IArrayTypeSymbol array) return IsRequestModel(array.ElementType, minimalApi);
        if (type.TypeKind is TypeKind.TypeParameter or TypeKind.Delegate or TypeKind.Pointer) return false;

        var name = type.Name;
        if (name is "IFormFile" or "IFormCollection" or "IFormFileCollection") return true;

        var ns = type.ContainingNamespace?.ToDisplayString() ?? "";
        if (type is INamedTypeSymbol { IsGenericType: true } generic && ns.StartsWith("System.Collections", StringComparison.Ordinal))
        {
            foreach (var argument in generic.TypeArguments)
                if (IsRequestModel(argument, minimalApi)) return true;
            return false;
        }

        if (type.TypeKind == TypeKind.Interface) return false; // injected services
        if (ns.StartsWith("System.Text.Json", StringComparison.Ordinal)) return true; // JsonElement, JsonDocument, JsonNode
        if (ns == "System" || ns.StartsWith("System.", StringComparison.Ordinal) || ns.StartsWith("Microsoft.", StringComparison.Ordinal))
            return false; // HttpContext, HttpClient, ILogger, ClaimsPrincipal ...
        if (type.InheritsFrom("Microsoft.EntityFrameworkCore.DbContext")) return false;

        if (!minimalApi) return true; // a controller binds every complex parameter from the request

        // Minimal APIs inject registered services into the same parameter list. A request model has settable data properties.
        foreach (var suffix in ServiceSuffixes)
            if (name.EndsWith(suffix, StringComparison.Ordinal)) return false;
        if (type.IsRecord) return true;
        foreach (var member in type.GetMembers())
            if (member is IPropertySymbol { DeclaredAccessibility: Accessibility.Public, SetMethod: not null, IsStatic: false }) return true;
        return false;
    }
}
