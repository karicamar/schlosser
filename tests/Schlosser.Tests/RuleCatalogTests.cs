using System.Reflection;
using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Schlosser.Tests;

/// <summary>The rule list, the analyzers and the documentation must not drift apart.</summary>
public class RuleCatalogTests
{
    private static readonly string Docs = File.ReadAllText(Path.Combine(FindRoot(), "docs", "rules.md"));

    [Fact]
    public void Rule_ids_are_unique_and_well_formed()
    {
        var ids = Rules.All.Select(r => r.Id).ToList();
        Assert.Equal(ids.Count, ids.Distinct().Count());
        Assert.All(ids, id => Assert.Matches(@"^SL\d{3}$", id));
    }

    [Fact]
    public void Every_rule_has_a_cwe_a_description_and_a_help_link()
    {
        Assert.All(Rules.All, rule =>
        {
            Assert.Matches(@"^CWE-\d+$", Rules.Cwe(rule));
            Assert.False(string.IsNullOrWhiteSpace(rule.Description.ToString()));
            Assert.EndsWith("#" + rule.Id.ToLowerInvariant(), rule.HelpLinkUri);
        });
    }

    [Fact]
    public void Every_rule_is_reported_by_exactly_one_analyzer()
    {
        var supported = typeof(Rules).Assembly.GetTypes()
            .Where(t => t.GetCustomAttribute<DiagnosticAnalyzerAttribute>() is not null)
            .Select(t => (DiagnosticAnalyzer)Activator.CreateInstance(t)!)
            .SelectMany(a => a.SupportedDiagnostics.Select(d => d.Id))
            .ToList();

        Assert.Equal(Rules.All.Select(r => r.Id).OrderBy(i => i), supported.OrderBy(i => i));
    }

    [Fact]
    public void Every_rule_is_documented_with_the_same_title_cwe_and_severity()
    {
        foreach (var rule in Rules.All)
        {
            Assert.Contains("### " + rule.Id, Docs);
            var row = Regex.Match(Docs, @"^\| \[" + rule.Id + @"\]\(#" + rule.Id.ToLowerInvariant() + @"\) \| (?<title>[^|]+) \| (?<cwe>[^|]+) \| (?<severity>[^|]+) \|", RegexOptions.Multiline);
            Assert.True(row.Success, rule.Id + " is missing in the table of docs/rules.md");
            Assert.Equal(rule.Title.ToString(), row.Groups["title"].Value.Trim());
            Assert.Equal(Rules.Cwe(rule), row.Groups["cwe"].Value.Trim());
            Assert.Equal(rule.DefaultSeverity == Microsoft.CodeAnalysis.DiagnosticSeverity.Info ? "note" : "warning", row.Groups["severity"].Value.Trim());
        }
    }

    [Fact]
    public void The_documentation_does_not_describe_rules_that_do_not_exist()
    {
        var documented = Regex.Matches(Docs, @"^### (SL\d{3})", RegexOptions.Multiline).Select(m => m.Groups[1].Value);
        Assert.Equal(Rules.All.Select(r => r.Id).OrderBy(i => i), documented.OrderBy(i => i));
    }

    [Fact]
    public void Rules_with_a_code_fix_are_marked_in_the_documentation()
    {
        var fixable = new Schlosser.CodeFixes.SchlosserCodeFixProvider().FixableDiagnosticIds;
        foreach (var rule in Rules.All)
        {
            var row = Regex.Match(Docs, @"^\| \[" + rule.Id + @"\].*$", RegexOptions.Multiline).Value;
            Assert.Equal(fixable.Contains(rule.Id), row.Contains("fix"));
        }
    }

    private static string FindRoot()
    {
        var folder = new DirectoryInfo(AppContext.BaseDirectory);
        while (folder is not null && !File.Exists(Path.Combine(folder.FullName, "Schlosser.slnx"))) folder = folder.Parent;
        return folder?.FullName ?? throw new InvalidOperationException("Schlosser.slnx not found above " + AppContext.BaseDirectory);
    }
}
