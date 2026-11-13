using System.Collections.Immutable;
using System.Text;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CodeActions;
using Microsoft.CodeAnalysis.CodeFixes;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Text;

namespace Schlosser.Tests;

/// <summary>
/// Small test harness: compiles a snippet against the real ASP.NET Core, EF Core, Dapper ... assemblies this test
/// project references, runs an analyzer and compares the diagnostics with the markers in the snippet.
///
/// Marker syntax: <c>{|SL001:expression|}</c> means "SL001 is reported exactly on this expression".
/// A snippet without markers must produce no diagnostics. Compile errors in a snippet fail the test,
/// so a typo can never make a "no findings" test pass by accident.
/// </summary>
internal static class Verify
{
    private const string GlobalUsings = """
        global using System;
        global using System.Collections.Generic;
        global using System.IO;
        global using System.Linq;
        global using System.Net.Http;
        global using System.Threading;
        global using System.Threading.Tasks;
        global using Microsoft.AspNetCore.Builder;
        global using Microsoft.AspNetCore.Http;
        global using Microsoft.AspNetCore.Mvc;
        global using Microsoft.Extensions.Logging;
        """;

    private static readonly Lazy<ImmutableArray<MetadataReference>> References = new(() =>
    {
        // Everything the test host itself can load: the .NET and ASP.NET Core frameworks and the referenced packages
        var paths = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator);
        // ... except the test framework: a snippet is production code, and SL030 behaves differently in test projects
        return paths.Where(File.Exists)
            .Where(p => !Path.GetFileName(p).StartsWith("xunit", StringComparison.OrdinalIgnoreCase)
                        && !Path.GetFileName(p).StartsWith("Microsoft.VisualStudio.TestPlatform", StringComparison.OrdinalIgnoreCase))
            .Select(p => (MetadataReference)MetadataReference.CreateFromFile(p)).ToImmutableArray();
    });

    public static Task Analyzer<TAnalyzer>(string markedSource) where TAnalyzer : DiagnosticAnalyzer, new() =>
        Analyzers(markedSource, new TAnalyzer());

    /// <summary>Like <see cref="Analyzer{TAnalyzer}"/>, for a file with a special name (generated Razor code).</summary>
    public static Task AnalyzerAt<TAnalyzer>(string path, string markedSource) where TAnalyzer : DiagnosticAnalyzer, new() =>
        Analyzers(markedSource, path, new DiagnosticAnalyzer[] { new TAnalyzer() });

    public static Task Analyzers(string markedSource, params DiagnosticAnalyzer[] analyzers) =>
        Analyzers(markedSource, "Snippet.cs", analyzers);

    private static async Task Analyzers(string markedSource, string path, DiagnosticAnalyzer[] analyzers)
    {
        var (source, expected) = ParseMarkers(markedSource);
        var diagnostics = await Run(source, path, analyzers);

        var actual = diagnostics.Select(d => (d.Id, d.Location.SourceSpan)).OrderBy(d => d.SourceSpan.Start).ThenBy(d => d.Id).ToList();
        var wanted = expected.OrderBy(d => d.Span.Start).ThenBy(d => d.Id).ToList();

        if (!actual.SequenceEqual(wanted))
        {
            var text = SourceText.From(source);
            string Describe(IEnumerable<(string Id, TextSpan Span)> items) => string.Join(Environment.NewLine,
                items.Select(i => $"  {i.Id} line {text.Lines.GetLinePosition(i.Span.Start).Line + 1}: {text.ToString(i.Span)}"));
            Assert.Fail($"Diagnostics differ.{Environment.NewLine}Expected:{Environment.NewLine}{Describe(wanted)}{Environment.NewLine}" +
                        $"Actual:{Environment.NewLine}{Describe(actual)}{Environment.NewLine}" +
                        string.Join(Environment.NewLine, diagnostics.Select(d => "  " + d.GetMessage())));
        }
    }

    /// <summary>The diagnostics of a snippet without markers, for tests that look at messages.</summary>
    public static async Task<ImmutableArray<Diagnostic>> Diagnostics<TAnalyzer>(string source) where TAnalyzer : DiagnosticAnalyzer, new() =>
        await Run(ParseMarkers(source).Source, new TAnalyzer());

    public static Task<ImmutableArray<Diagnostic>> Run(string source, params DiagnosticAnalyzer[] analyzers) =>
        Run(source, "Snippet.cs", analyzers);

    private static async Task<ImmutableArray<Diagnostic>> Run(string source, string path, DiagnosticAnalyzer[] analyzers)
    {
        var compilation = Compile(source, path);
        var errors = compilation.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error).ToList();
        Assert.True(errors.Count == 0, "The test snippet does not compile:" + Environment.NewLine + string.Join(Environment.NewLine, errors));

        var withAnalyzers = compilation.WithAnalyzers(analyzers.ToImmutableArray());
        var diagnostics = await withAnalyzers.GetAnalyzerDiagnosticsAsync();
        var crashes = diagnostics.Where(d => d.Id == "AD0001").ToList();
        Assert.True(crashes.Count == 0, "Analyzer crashed: " + string.Join(Environment.NewLine, crashes.Select(c => c.GetMessage())));
        return diagnostics.OrderBy(d => d.Location.SourceSpan.Start).ToImmutableArray();
    }

    public static CSharpCompilation Compile(string source, string path = "Snippet.cs")
    {
        var options = new CSharpParseOptions(LanguageVersion.Latest);
        return CSharpCompilation.Create("Snippet",
            new[]
            {
                CSharpSyntaxTree.ParseText(source, options, path: path),
                CSharpSyntaxTree.ParseText(GlobalUsings, options, path: "GlobalUsings.cs"),
            },
            References.Value,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary, nullableContextOptions: NullableContextOptions.Enable));
    }

    /// <summary>Applies the code fix to the first diagnostic of the analyzer and compares the result.</summary>
    public static async Task CodeFix<TAnalyzer, TFix>(string before, string after, int fixIndex = 0)
        where TAnalyzer : DiagnosticAnalyzer, new()
        where TFix : CodeFixProvider, new()
    {
        var (source, _) = ParseMarkers(before);
        using var workspace = new AdhocWorkspace();
        var projectId = ProjectId.CreateNewId();
        var solution = workspace.CurrentSolution
            .AddProject(projectId, "Snippet", "Snippet", LanguageNames.CSharp)
            .WithProjectCompilationOptions(projectId, new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary, nullableContextOptions: NullableContextOptions.Enable))
            .WithProjectParseOptions(projectId, new CSharpParseOptions(LanguageVersion.Latest))
            .AddMetadataReferences(projectId, References.Value)
            .AddDocument(DocumentId.CreateNewId(projectId), "GlobalUsings.cs", GlobalUsings);
        var documentId = DocumentId.CreateNewId(projectId);
        solution = solution.AddDocument(documentId, "Snippet.cs", source);

        var fix = new TFix();
        for (var round = 0; round < 10; round++)
        {
            var document = solution.GetDocument(documentId)!;
            var compilation = (await document.Project.GetCompilationAsync())!;
            var diagnostics = (await compilation.WithAnalyzers(ImmutableArray.Create<DiagnosticAnalyzer>(new TAnalyzer())).GetAnalyzerDiagnosticsAsync())
                .Where(d => fix.FixableDiagnosticIds.Contains(d.Id) && d.Location.SourceTree?.FilePath == "Snippet.cs")
                .OrderBy(d => d.Location.SourceSpan.Start).ToList();
            if (diagnostics.Count == 0)
            {
                Assert.True(round > 0, "The analyzer reported nothing to fix.");
                break;
            }

            var actions = new List<CodeAction>();
            var context = new CodeFixContext(document, diagnostics[0], (action, _) => actions.Add(action), CancellationToken.None);
            await fix.RegisterCodeFixesAsync(context);
            Assert.True(actions.Count > fixIndex, $"No code fix offered for {diagnostics[0].Id}: {diagnostics[0].GetMessage()}");

            var operations = await actions[fixIndex].GetOperationsAsync(CancellationToken.None);
            solution = operations.OfType<ApplyChangesOperation>().Single().ChangedSolution;
        }

        var result = (await solution.GetDocument(documentId)!.GetTextAsync()).ToString();
        Assert.Equal(Normalize(after), Normalize(result));

        // The fixed code must still compile
        var fixedCompilation = (await solution.GetProject(projectId)!.GetCompilationAsync())!;
        var errors = fixedCompilation.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error).ToList();
        Assert.True(errors.Count == 0, "The fixed code does not compile:" + Environment.NewLine + string.Join(Environment.NewLine, errors));
    }

    private static string Normalize(string text) => text.Replace("\r\n", "\n").Trim();

    private static (string Source, List<(string Id, TextSpan Span)> Expected) ParseMarkers(string marked)
    {
        var source = new StringBuilder();
        var expected = new List<(string, TextSpan)>();
        var open = new Stack<(string Id, int Start)>();

        for (var i = 0; i < marked.Length; i++)
        {
            if (marked[i] == '{' && i + 1 < marked.Length && marked[i + 1] == '|')
            {
                var colon = marked.IndexOf(':', i);
                open.Push((marked.Substring(i + 2, colon - i - 2), source.Length));
                i = colon;
            }
            else if (marked[i] == '|' && i + 1 < marked.Length && marked[i + 1] == '}' && open.Count > 0)
            {
                var (id, start) = open.Pop();
                expected.Add((id, TextSpan.FromBounds(start, source.Length)));
                i++;
            }
            else
            {
                source.Append(marked[i]);
            }
        }

        return (source.ToString(), expected);
    }
}
