using System.Collections.Generic;
using System.Collections.Immutable;
using System.Composition;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CodeActions;
using Microsoft.CodeAnalysis.CodeFixes;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Editing;
using Microsoft.CodeAnalysis.Formatting;
using Microsoft.CodeAnalysis.Simplification;
using static Microsoft.CodeAnalysis.CSharp.SyntaxFactory;

namespace Schlosser.CodeFixes;

/// <summary>
/// Fixes for the rules where the safe code can be written mechanically. Injection through several methods,
/// hard-coded secrets and disabled certificate validation need a decision by the developer and get no automatic fix.
/// </summary>
[ExportCodeFixProvider(LanguageNames.CSharp, Name = nameof(SchlosserCodeFixProvider)), Shared]
public sealed class SchlosserCodeFixProvider : CodeFixProvider
{
    private const string Crypto = "System.Security.Cryptography.";

    private static readonly Dictionary<string, string> InterpolatedSqlMethods = new()
    {
        ["FromSqlRaw"] = "FromSqlInterpolated",
        ["ExecuteSqlRaw"] = "ExecuteSqlInterpolated",
        ["ExecuteSqlRawAsync"] = "ExecuteSqlInterpolatedAsync",
        ["SqlQueryRaw"] = "SqlQuery",
    };

    public override ImmutableArray<string> FixableDiagnosticIds { get; } =
        ImmutableArray.Create("SL001", "SL005", "SL020", "SL022", "SL025", "SL034", "SL035", "SL036", "SL042");

    public override FixAllProvider GetFixAllProvider() => WellKnownFixAllProviders.BatchFixer;

    public override async Task RegisterCodeFixesAsync(CodeFixContext context)
    {
        var root = await context.Document.GetSyntaxRootAsync(context.CancellationToken).ConfigureAwait(false);
        if (root is null) return;

        foreach (var diagnostic in context.Diagnostics)
        {
            var node = root.FindNode(diagnostic.Location.SourceSpan, getInnermostNodeForTie: true);
            Fix? fix = diagnostic.Id switch
            {
                "SL001" => InterpolatedSql(node),
                "SL005" => LocalRedirect(node),
                "SL020" => Sha256(node),
                "SL022" => CryptoRandom(node),
                "SL025" => await FixedTimeEquals(context.Document, node, context.CancellationToken).ConfigureAwait(false),
                "SL034" => SafeXml(node),
                "SL035" => SetTrue(node, "Switch the check on"),
                "SL036" => CookieFlags(node, diagnostic),
                "SL042" => node is LiteralExpressionSyntax literal && literal.IsKind(SyntaxKind.FalseLiteralExpression)
                    ? new Fix("Count failed sign-ins", literal, LiteralExpression(SyntaxKind.TrueLiteralExpression))
                    : SetTrue(node, "Lock new accounts too"),
                _ => null,
            };
            if (fix is null) continue;

            var document = context.Document;
            context.RegisterCodeFix(
                CodeAction.Create(fix.Title, cancellation => Apply(document, fix, cancellation), equivalenceKey: diagnostic.Id + fix.Title),
                diagnostic);
        }
    }

    private sealed class Fix
    {
        public Fix(string title, SyntaxNode old, SyntaxNode replacement)
        {
            Title = title;
            Old = old;
            Replacement = replacement;
        }

        public string Title { get; }
        public SyntaxNode Old { get; }
        public SyntaxNode Replacement { get; }
    }

    private static async Task<Document> Apply(Document document, Fix fix, CancellationToken cancellation)
    {
        var editor = await DocumentEditor.CreateAsync(document, cancellation).ConfigureAwait(false);
        editor.ReplaceNode(fix.Old, fix.Replacement
            .WithTriviaFrom(fix.Old)
            .WithAdditionalAnnotations(Simplifier.Annotation, Simplifier.AddImportsAnnotation, Formatter.Annotation));
        var changed = editor.GetChangedDocument();

        // Fully qualified names in the replacement become a using directive plus the short name
        changed = await ImportAdder.AddImportsAsync(changed, Simplifier.Annotation, cancellationToken: cancellation).ConfigureAwait(false);
        changed = await Simplifier.ReduceAsync(changed, Simplifier.Annotation, cancellationToken: cancellation).ConfigureAwait(false);
        return await Formatter.FormatAsync(changed, Formatter.Annotation, cancellationToken: cancellation).ConfigureAwait(false);
    }

    private static T? Ancestor<T>(SyntaxNode node) where T : SyntaxNode => node.FirstAncestorOrSelf<T>();

    private static SimpleNameSyntax? CalledName(InvocationExpressionSyntax invocation) => invocation.Expression switch
    {
        MemberAccessExpressionSyntax member => member.Name,
        SimpleNameSyntax name => name,
        _ => null,
    };

    private static SimpleNameSyntax Renamed(SimpleNameSyntax name, string newName) =>
        name.WithIdentifier(Identifier(newName).WithTriviaFrom(name.Identifier));

    // ------------------------------------------------------------------ SL001

    /// <summary>
    /// FromSqlRaw($"... WHERE Name = '{name}'")  →  FromSqlInterpolated($"... WHERE Name = {name}").
    /// EF Core turns every hole of an interpolated SQL string into a parameter. The quotes around a hole must go,
    /// otherwise the parameter marker itself would be inside a SQL string.
    /// </summary>
    private static Fix? InterpolatedSql(SyntaxNode node)
    {
        if (node is ArgumentSyntax argument) node = argument.Expression;
        if (node is not InterpolatedStringExpressionSyntax interpolated) return null;
        if (interpolated.Parent?.Parent?.Parent is not InvocationExpressionSyntax invocation) return null;
        var name = CalledName(invocation);
        if (name is null || !InterpolatedSqlMethods.TryGetValue(name.Identifier.ValueText, out var replacement)) return null;

        var contents = interpolated.Contents;
        var rewritten = new List<InterpolatedStringContentSyntax>();
        for (var i = 0; i < contents.Count; i++)
        {
            if (contents[i] is not InterpolatedStringTextSyntax text)
            {
                rewritten.Add(contents[i]);
                continue;
            }

            var raw = text.TextToken.Text;
            var value = text.TextToken.ValueText;
            var holeBefore = i > 0 && contents[i - 1] is InterpolationSyntax;
            var holeAfter = i + 1 < contents.Count && contents[i + 1] is InterpolationSyntax;
            if (holeBefore && raw.StartsWith("'"))
            {
                raw = raw.Substring(1);
                value = value.Substring(1);
            }

            if (holeAfter && raw.EndsWith("'"))
            {
                raw = raw.Substring(0, raw.Length - 1);
                value = value.Substring(0, value.Length - 1);
            }

            if (raw.Length > 0)
                rewritten.Add(text.WithTextToken(Token(default, SyntaxKind.InterpolatedStringTextToken, raw, value, default)));
        }

        var newInvocation = invocation
            .ReplaceNodes(new SyntaxNode[] { name, interpolated }, (original, _) =>
                original == name ? Renamed(name, replacement) : interpolated.WithContents(List(rewritten)));
        return new Fix($"Use {replacement} (values become parameters)", invocation, newInvocation);
    }

    // ------------------------------------------------------------------ SL005

    private static Fix? LocalRedirect(SyntaxNode node)
    {
        var invocation = Ancestor<InvocationExpressionSyntax>(node);
        while (invocation is not null && CalledName(invocation)?.Identifier.ValueText.StartsWith("Redirect") != true)
            invocation = invocation.Parent is null ? null : Ancestor<InvocationExpressionSyntax>(invocation.Parent);
        if (invocation is null) return null;

        var name = CalledName(invocation)!;
        var receiver = (invocation.Expression as MemberAccessExpressionSyntax)?.Expression.ToString();
        if (receiver is not (null or "this" or "base" or "Results" or "TypedResults")) return null; // Response.Redirect has no local variant
        if (receiver is "Results" or "TypedResults" && name.Identifier.ValueText != "Redirect") return null;

        var local = "Local" + name.Identifier.ValueText;
        return new Fix($"Use {local} (only addresses of this site)", name, Renamed(name, local));
    }

    // ------------------------------------------------------------------ SL020

    private static Fix? Sha256(SyntaxNode node)
    {
        switch (node)
        {
            // MD5.Create(), SHA1.HashData(data)
            case InvocationExpressionSyntax { Expression: MemberAccessExpressionSyntax member } when TypeName(member.Expression) is "MD5" or "SHA1":
                return new Fix("Use SHA-256", member.Expression, ParseExpression(Crypto + "SHA256"));

            // HashAlgorithmName.SHA1
            case MemberAccessExpressionSyntax { Name.Identifier.ValueText: "SHA1" or "MD5" } algorithm:
                return new Fix("Use SHA-256", algorithm.Name, IdentifierName("SHA256"));

            case ObjectCreationExpressionSyntax creation when TypeName(creation.Type) is "HMACMD5":
                return new Fix("Use HMAC-SHA256", creation.Type, ParseTypeName(Crypto + "HMACSHA256"));

            // new MD5CryptoServiceProvider(), new SHA1Managed()
            case ObjectCreationExpressionSyntax creation:
                return new Fix("Use SHA-256", creation, ParseExpression(Crypto + "SHA256.Create()"));

            default:
                return null;
        }
    }

    private static string TypeName(SyntaxNode node) => node switch
    {
        QualifiedNameSyntax qualified => qualified.Right.Identifier.ValueText,
        MemberAccessExpressionSyntax member => member.Name.Identifier.ValueText,
        SimpleNameSyntax simple => simple.Identifier.ValueText,
        _ => "",
    };

    // ------------------------------------------------------------------ SL022

    private static Fix? CryptoRandom(SyntaxNode node)
    {
        if (node is not InvocationExpressionSyntax invocation || CalledName(invocation) is not { } name) return null;
        var arguments = invocation.ArgumentList;

        switch (name.Identifier.ValueText)
        {
            case "Next" when arguments.Arguments.Count is 1 or 2:
                return new Fix("Use RandomNumberGenerator.GetInt32", invocation,
                    InvocationExpression(ParseExpression(Crypto + "RandomNumberGenerator.GetInt32"), arguments));
            case "NextBytes" when arguments.Arguments.Count == 1:
                return new Fix("Use RandomNumberGenerator.Fill", invocation,
                    InvocationExpression(ParseExpression(Crypto + "RandomNumberGenerator.Fill"), arguments));
            default:
                return null;
        }
    }

    // ------------------------------------------------------------------ SL025

    private static async Task<Fix?> FixedTimeEquals(Document document, SyntaxNode node, CancellationToken cancellation)
    {
        var model = await document.GetSemanticModelAsync(cancellation).ConfigureAwait(false);
        if (model is null) return null;

        ExpressionSyntax left, right;
        var negate = false;
        switch (node)
        {
            case BinaryExpressionSyntax binary:
                left = binary.Left;
                right = binary.Right;
                negate = binary.IsKind(SyntaxKind.NotEqualsExpression);
                break;
            case InvocationExpressionSyntax { Expression: MemberAccessExpressionSyntax member } invocation
                when invocation.ArgumentList.Arguments.Count >= 1:
                if (member.Expression.ToString() is "string" or "String" && invocation.ArgumentList.Arguments.Count >= 2)
                {
                    left = invocation.ArgumentList.Arguments[0].Expression;
                    right = invocation.ArgumentList.Arguments[1].Expression;
                }
                else
                {
                    left = member.Expression;
                    right = invocation.ArgumentList.Arguments[0].Expression;
                }
                break;
            default:
                return null;
        }

        ExpressionSyntax Bytes(ExpressionSyntax expression)
        {
            var type = model.GetTypeInfo(expression, cancellation).Type;
            if (type?.SpecialType != SpecialType.System_String) return expression.WithoutTrivia();
            return InvocationExpression(ParseExpression("System.Text.Encoding.UTF8.GetBytes"),
                ArgumentList(SingletonSeparatedList(Argument(expression.WithoutTrivia()))));
        }

        ExpressionSyntax call = InvocationExpression(
            ParseExpression(Crypto + "CryptographicOperations.FixedTimeEquals"),
            ArgumentList(SeparatedList(new[] { Argument(Bytes(left)), Argument(Bytes(right)) })));
        if (negate) call = PrefixUnaryExpression(SyntaxKind.LogicalNotExpression, call);
        return new Fix("Compare in constant time (FixedTimeEquals)", node, call);
    }

    // ------------------------------------------------------------------ SL034, SL035, SL036

    private static Fix? SafeXml(SyntaxNode node)
    {
        if (Ancestor<AssignmentExpressionSyntax>(node) is not { } assignment) return null;
        var property = TypeName(assignment.Left);
        if (property == "DtdProcessing" && assignment.Right is MemberAccessExpressionSyntax value)
            return new Fix("Prohibit DTDs", value.Name, IdentifierName("Prohibit"));
        if (property == "XmlResolver")
            return new Fix("Remove the resolver", assignment.Right, LiteralExpression(SyntaxKind.NullLiteralExpression));
        if (property == "ProhibitDtd")
            return new Fix("Prohibit DTDs", assignment.Right, LiteralExpression(SyntaxKind.TrueLiteralExpression));
        return null;
    }

    private static Fix? SetTrue(SyntaxNode node, string title)
    {
        if (Ancestor<AssignmentExpressionSyntax>(node) is not { } assignment) return null;
        if (!assignment.Right.IsKind(SyntaxKind.FalseLiteralExpression)) return null;
        return new Fix(title, assignment.Right, LiteralExpression(SyntaxKind.TrueLiteralExpression));
    }

    private static Fix? CookieFlags(SyntaxNode node, Diagnostic diagnostic)
    {
        if (node is AssignmentExpressionSyntax or ExpressionStatementSyntax)
        {
            var assignment = node as AssignmentExpressionSyntax ?? (node as ExpressionStatementSyntax)?.Expression as AssignmentExpressionSyntax;
            if (assignment is null) return null;
            if (TypeName(assignment.Left) == "SecurePolicy" && assignment.Right is MemberAccessExpressionSyntax policy)
                return new Fix("Send the cookie only over HTTPS", policy.Name, IdentifierName("Always"));
            return SetTrue(assignment, "Set the flag");
        }

        if (node is not BaseObjectCreationExpressionSyntax creation) return null;
        if (!diagnostic.Properties.TryGetValue("Missing", out var missing) || missing is null) return null;

        var additions = new List<ExpressionSyntax>();
        if (missing.Contains("Secure")) additions.Add(ParseExpression("Secure = true"));
        if (missing.Contains("HttpOnly")) additions.Add(ParseExpression("HttpOnly = true"));

        var existing = creation.Initializer?.Expressions ?? default;
        var initializer = InitializerExpression(SyntaxKind.ObjectInitializerExpression, SeparatedList(existing.Concat(additions)));
        return new Fix("Add " + missing, creation, creation.WithInitializer(initializer));
    }
}
