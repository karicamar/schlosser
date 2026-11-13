namespace Schlosser.Tests;

public class RazorTests
{
    // What the Razor source generator produces for a view, reduced to the calls that matter
    private const string View = """
        using Microsoft.AspNetCore.Html;
        using Microsoft.AspNetCore.Mvc.Rendering;

        public class BlogEntry { public string Title { get; set; } = ""; public string Contents { get; set; } = ""; public int Likes { get; set; } }

        public class Views_Blog_Index
        {
            public IHtmlHelper<BlogEntry> Html { get; set; } = null!;
            public IJsonHelper Json { get; set; } = null!;
            public BlogEntry Model { get; set; } = null!;

            public void Execute()
            {
                Write(Html.Raw({|SL012:Model.Contents|}));
                Write(Html.Raw({|SL012:"<b>" + Model.Title + "</b>"|}));
                Write(Html.Raw({|SL012:Newtonsoft.Json.JsonConvert.SerializeObject(Model)|}));

                Write(Html.Raw("<hr />"));
                Write(Html.Raw(Model.Likes));
                Write(Html.Raw(Json.Serialize(Model)));
                Write(Html.Raw(System.Text.Json.JsonSerializer.Serialize(Model)));
                Write(Html.Raw(new HtmlString("<br />")));
                Write(Html.Raw(Sanitize(Model.Contents)));
                Write(Model.Contents); // @Model.Contents is encoded by Razor
            }

            private static string Sanitize(string html) => html;
            private void Write(object? value) { }
        }
        """;

    [Fact]
    public Task Html_raw_in_a_generated_view() =>
        Verify.AnalyzerAt<RazorAnalyzer>("Views_Blog_Index_cshtml.g.cs", View);

    [Fact]
    public Task Ordinary_code_is_left_to_the_taint_analysis()
    {
        var withoutMarkers = View.Replace("{|SL012:", "").Replace("|}", "");
        return Verify.AnalyzerAt<RazorAnalyzer>("HtmlHelpers.cs", withoutMarkers);
    }
}
