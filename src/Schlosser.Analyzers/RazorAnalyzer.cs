using System;
using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace Schlosser;

/// <summary>
/// SL012: Html.Raw in Razor views. Views are compiled to C# by the Razor source generator, so this is the one analyzer
/// that looks at generated code. The compiler maps the location back to the line in the .cshtml file.
///
/// There is no taint tracking here: what a view prints usually comes from the database (stored XSS),
/// and whether a database column holds user input cannot be seen in the code. So every Html.Raw of a value is reported,
/// except the usual safe uses: constants, serialized JSON, values that are already IHtmlContent and sanitizer calls.
/// </summary>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class RazorAnalyzer : DiagnosticAnalyzer
{
    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } = ImmutableArray.Create(Rules.RawHtmlInView);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.Analyze | GeneratedCodeAnalysisFlags.ReportDiagnostics);
        context.EnableConcurrentExecution();
        context.RegisterOperationAction(Analyze, OperationKind.Invocation);
    }

    private static void Analyze(OperationAnalysisContext context)
    {
        var invocation = (IInvocationOperation)context.Operation;
        var method = invocation.TargetMethod;
        if (method.Name != "Raw" || invocation.Arguments.Length != 1) return;
        if (!method.ContainingType.IsOrImplements("Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper")) return;
        if (!IsRazorFile(invocation.Syntax.SyntaxTree.FilePath)) return; // .cs files are covered by the taint analysis (SL007)

        var value = invocation.Arguments[0].Value.Unwrap();
        if (value.ConstantValue.HasValue) return;
        if (value.Type.IsOrImplements("Microsoft.AspNetCore.Html.IHtmlContent")) return;
        if (value.Type is { } type && !Taint.Carrier.CanCarry(type)) return; // numbers, dates

        if (value is IInvocationOperation call)
        {
            var name = call.TargetMethod.Name;
            var owner = call.TargetMethod.ContainingType;
            // System.Text.Json escapes < > & by default; Newtonsoft.Json does not and stays reported
            if (name == "Serialize" && (owner.Is("System.Text.Json.JsonSerializer") || owner.IsOrImplements("Microsoft.AspNetCore.Mvc.Rendering.IJsonHelper")))
                return;
            if (name.StartsWith("Sanitize", StringComparison.Ordinal) || name.IndexOf("Encode", StringComparison.Ordinal) >= 0) return;
        }

        var text = value.Syntax.ToString();
        context.ReportDiagnostic(Diagnostic.Create(Rules.RawHtmlInView, value.Syntax.GetLocation(), text.Length > 60 ? "a value" : "'" + text + "'"));
    }

    private static bool IsRazorFile(string path) =>
        path.IndexOf("cshtml", StringComparison.OrdinalIgnoreCase) >= 0 || path.IndexOf("razor", StringComparison.OrdinalIgnoreCase) >= 0;
}
