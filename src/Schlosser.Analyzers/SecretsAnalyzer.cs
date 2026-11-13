using System;
using System.Collections.Immutable;
using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace Schlosser;

/// <summary>
/// SL030: secrets written into the source. Three signals:
/// a literal with the format of a real credential (AWS key, GitHub token, private key ...),
/// a connection string with a password, and a literal stored under a secret name (password, apiKey, clientSecret).
/// The secret itself is never repeated in the message, so it does not spread into build logs and SARIF files.
/// </summary>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class SecretsAnalyzer : DiagnosticAnalyzer
{
    private const RegexOptions Options = RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture;

    private static readonly (Regex Pattern, string Name)[] KnownFormats =
    {
        (new Regex(@"\b(AKIA|ASIA)[0-9A-Z]{16}\b", Options), "an AWS access key id"),
        (new Regex(@"\bgh[pousr]_[A-Za-z0-9]{36,}\b", Options), "a GitHub token"),
        (new Regex(@"\bgithub_pat_[A-Za-z0-9_]{50,}\b", Options), "a GitHub fine-grained token"),
        (new Regex(@"\bxox[baprs]-[A-Za-z0-9-]{10,}", Options), "a Slack token"),
        (new Regex(@"-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----", Options), "a private key"),
        (new Regex(@"\b[sr]k_live_[0-9a-zA-Z]{24,}\b", Options), "a Stripe live key"),
        (new Regex(@"\bAIza[0-9A-Za-z_-]{35}\b", Options), "a Google API key"),
        (new Regex(@"\bSG\.[\w-]{22}\.[\w-]{43}\b", Options), "a SendGrid API key"),
        (new Regex(@"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", Options), "a JSON Web Token"),
        (new Regex(@"AccountKey=[A-Za-z0-9+/=]{40,}", Options), "an Azure storage account key"),
        (new Regex(@"\bsk-ant-[A-Za-z0-9_-]{20,}", Options), "an Anthropic API key"),
    };

    private static readonly Regex ConnectionStringPassword =
        new(@"(^|;)\s*(password|pwd)\s*=\s*(?<value>[^;]+)", Options | RegexOptions.IgnoreCase);

    private static readonly Regex UrlWithPassword =
        new(@"^[a-z][a-z0-9+.-]*://[^/\s:@]+:(?<value>[^/\s@]+)@", Options | RegexOptions.IgnoreCase);

    private static readonly string[] Placeholders =
    {
        "<", "{", "xxx", "***", "...", "your", "example", "placeholder", "todo", "change", "replace", "dummy", "sample", "redacted", "secret_here", "insert",
    };

    private static readonly string[] TestFrameworks =
        { "xunit.core", "xunit.v3.core", "nunit.framework", "Microsoft.VisualStudio.TestPlatform.TestFramework", "TUnit.Core" };

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } = ImmutableArray.Create(Rules.HardCodedSecret);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterCompilationStartAction(start =>
        {
            // Test projects are full of made-up passwords. Real credential formats are still reported there.
            var isTestProject = false;
            foreach (var reference in start.Compilation.ReferencedAssemblyNames)
                if (Array.IndexOf(TestFrameworks, reference.Name) >= 0) isTestProject = true;

            start.RegisterOperationAction(c => AnalyzeLiteral(c, isTestProject), OperationKind.Literal);
        });
    }

    private static void AnalyzeLiteral(OperationAnalysisContext context, bool isTestProject)
    {
        var literal = (ILiteralOperation)context.Operation;
        if (literal.ConstantValue.Value is not string text || text.Length < 4) return;

        foreach (var (pattern, name) in KnownFormats)
        {
            if (!pattern.IsMatch(text)) continue;
            Report(context, literal, "the text has the format of " + name);
            return;
        }

        if (isTestProject) return;

        var match = ConnectionStringPassword.Match(text);
        if (match.Success && text.IndexOf('=') != text.LastIndexOf('=') && IsRealValue(match.Groups["value"].Value.Trim(), minimumLength: 1))
        {
            Report(context, literal, "the connection string contains a password");
            return;
        }

        match = UrlWithPassword.Match(text);
        if (match.Success && IsRealValue(match.Groups["value"].Value, minimumLength: 1))
        {
            Report(context, literal, "the address contains a password");
            return;
        }

        var receiver = Names.Receiver(literal);
        if (receiver is null || !Names.IsSecret(receiver)) return;
        if (!IsRealValue(text, minimumLength: 4) || LooksLikeAName(text, receiver)) return;
        Report(context, literal, $"'{receiver}' is set to a text written in the source");
    }

    private static void Report(OperationAnalysisContext context, IOperation literal, string what) =>
        context.ReportDiagnostic(Diagnostic.Create(Rules.HardCodedSecret, literal.Syntax.GetLocation(), what));

    private static bool IsRealValue(string value, int minimumLength)
    {
        if (value.Length < minimumLength) return false;
        var lower = value.ToLowerInvariant();
        foreach (var placeholder in Placeholders)
            if (lower.Contains(placeholder)) return false;
        return true;
    }

    /// <summary>
    /// Values that name a secret instead of being one: a configuration key ("Jwt:Key"), an environment variable ("API_TOKEN"),
    /// a header or form field ("X-Api-Key", "password"), or a sentence for the user ("Enter your password").
    /// </summary>
    private static bool LooksLikeAName(string value, string receiver)
    {
        if (value.IndexOf(' ') != value.LastIndexOf(' ')) return true; // two or more spaces: a sentence
        if (string.Equals(value, receiver, StringComparison.OrdinalIgnoreCase)) return true;

        // only letters, separators and no digits: "Jwt:SigningKey", "X-Api-Key", "DB_PASSWORD", "access_token", "ConnectionStrings:Default"
        var hasSeparator = false;
        foreach (var c in value)
        {
            if (char.IsDigit(c)) return false;
            if (c is ':' or '_' or '-' or '.') hasSeparator = true;
            else if (!char.IsLetter(c)) return false;
        }

        if (hasSeparator) return true;

        // a word that is itself a secret name: "password", "token", "apiKey", "ClientSecret" (form fields, claim names, config keys)
        return Names.IsSecret(value);
    }
}
