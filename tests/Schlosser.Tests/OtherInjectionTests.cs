namespace Schlosser.Tests;

public class OtherInjectionTests
{
    // ---------------------------------------------------------------- SL003 command injection

    [Fact]
    public Task Command_injection_through_process_start()
    {
        return Verify.Analyzer<InjectionAnalyzer>("""
            using System.Diagnostics;

            public class ToolsController : ControllerBase
            {
                public IActionResult Ping(string host)
                {
                    Process.Start("ping", {|SL003:"-c 1 " + host|});
                    var info = new ProcessStartInfo("cmd.exe", {|SL003:$"/c nslookup {host}"|});
                    var other = new ProcessStartInfo { FileName = "/bin/sh", Arguments = {|SL003:"-c \"dig " + host + "\""|} };
                    other.FileName = {|SL003:host|};
                    return Ok();
                }

                public IActionResult Fixed(int count)
                {
                    Process.Start("ping", "-c " + count + " example.org");
                    return Ok();
                }
            }
            """);
    }

    [Fact]
    public Task Command_injection_across_a_service()
    {
        return Verify.Analyzer<InjectionAnalyzer>("""
            using System.Diagnostics;

            public class ConvertController : ControllerBase
            {
                private readonly Converter _converter = new();
                public IActionResult Convert([FromQuery] string file) => Ok(_converter.ToPdf(file));
            }

            public class Converter
            {
                public int ToPdf(string input)
                {
                    using var process = Process.Start("soffice", {|SL003:"--convert-to pdf " + input|});
                    return process.Id;
                }
            }
            """);
    }

    // ---------------------------------------------------------------- SL004 path traversal

    [Fact]
    public Task Path_traversal_and_its_fixes()
    {
        return Verify.Analyzer<InjectionAnalyzer>("""
            public class FilesController : ControllerBase
            {
                private const string Root = "/var/app/uploads";

                public IActionResult Download(string name)
                {
                    var bytes = System.IO.File.ReadAllBytes({|SL004:Path.Combine(Root, name)|});
                    return File(bytes, "application/octet-stream");
                }

                public IActionResult Open(string name) => PhysicalFile({|SL004:Root + "/" + name|}, "application/pdf");

                public IActionResult DownloadByFileName(string name)
                {
                    var bytes = System.IO.File.ReadAllBytes(Path.Combine(Root, Path.GetFileName(name)));
                    return File(bytes, "application/octet-stream");
                }

                public IActionResult DownloadChecked(string name)
                {
                    var full = Path.GetFullPath(Path.Combine(Root, name));
                    if (!full.StartsWith(Root + Path.DirectorySeparatorChar, StringComparison.Ordinal)) return BadRequest();
                    return File(System.IO.File.ReadAllBytes(full), "application/octet-stream");
                }

                public IActionResult DownloadById(int id) =>
                    File(System.IO.File.ReadAllBytes(Path.Combine(Root, id + ".pdf")), "application/pdf");
            }
            """);
    }

    [Fact]
    public Task Uploaded_file_name_is_request_data()
    {
        return Verify.Analyzer<InjectionAnalyzer>("""
            public class UploadController : ControllerBase
            {
                [HttpPost]
                public async Task<IActionResult> Upload(IFormFile file)
                {
                    await using var bad = new FileStream({|SL004:Path.Combine("uploads", file.FileName)|}, FileMode.Create);
                    await file.CopyToAsync(bad);

                    var safeName = Guid.NewGuid() + Path.GetExtension(file.FileName);
                    await using var good = new FileStream(Path.Combine("uploads", safeName), FileMode.Create);
                    await file.CopyToAsync(good);
                    return Ok();
                }
            }
            """);
    }

    // ---------------------------------------------------------------- SL005 open redirect

    [Fact]
    public Task Open_redirect_and_its_fixes()
    {
        return Verify.Analyzer<InjectionAnalyzer>("""
            public class AccountController : ControllerBase
            {
                public IActionResult Login(string returnUrl) => Redirect({|SL005:returnUrl|});

                public IActionResult LoginPermanent(string returnUrl) => RedirectPermanent({|SL005:returnUrl ?? "/"|});

                public void Raw(string next) => Response.Redirect({|SL005:next|});

                public IActionResult LoginChecked(string returnUrl)
                {
                    if (!Url.IsLocalUrl(returnUrl)) returnUrl = "/";
                    return Redirect(returnUrl);
                }

                public IActionResult LoginLocal(string returnUrl) => LocalRedirect(returnUrl);

                public IActionResult Details(int id) => Redirect("/orders/" + id);

                public IActionResult Home() => Redirect("/");
            }
            """);
    }

    [Fact]
    public Task Open_redirect_in_minimal_api()
    {
        return Verify.Analyzer<InjectionAnalyzer>("""
            public static class Endpoints
            {
                public static void Map(WebApplication app)
                {
                    app.MapGet("/go", (string to) => Results.Redirect({|SL005:to|}));
                    app.MapGet("/home", () => Results.Redirect("/"));
                    app.MapGet("/back", (string to) => Results.LocalRedirect(to));
                }
            }
            """);
    }

    // ---------------------------------------------------------------- SL006 SSRF

    [Fact]
    public Task Ssrf_only_when_the_request_decides_the_host()
    {
        return Verify.Analyzer<InjectionAnalyzer>("""
            public class Options { public string BaseUrl { get; set; } = ""; }

            public class ProxyController : ControllerBase
            {
                private readonly HttpClient _http = new();
                private readonly Options _options = new();

                public async Task<IActionResult> Fetch(string url) => Ok(await _http.GetStringAsync({|SL006:url|}));

                public async Task<IActionResult> FetchUri(string url) => Ok(await _http.GetAsync({|SL006:new Uri(url)|}));

                public async Task<IActionResult> Subdomain(string tenant) =>
                    Ok(await _http.GetStringAsync({|SL006:"https://" + tenant + ".example.com/status"|}));

                public async Task<IActionResult> Message(string target)
                {
                    using var request = new HttpRequestMessage(HttpMethod.Get, {|SL006:target|});
                    return Ok(await _http.SendAsync(request));
                }

                // The host is fixed: the request only chooses a path or query value
                public async Task<IActionResult> Rates(string currency) =>
                    Ok(await _http.GetStringAsync("https://api.example.com/rates/" + currency));

                public async Task<IActionResult> Relative(string id) => Ok(await _http.GetStringAsync($"api/users/{id}"));

                public async Task<IActionResult> Configured(string id) =>
                    Ok(await _http.GetStringAsync($"{_options.BaseUrl}/users/{id}"));

                public async Task<IActionResult> Escaped(string term) =>
                    Ok(await _http.GetStringAsync(Uri.EscapeDataString(term)));
            }
            """);
    }

    // ---------------------------------------------------------------- SL007 XSS

    [Fact]
    public Task Xss_raw_html()
    {
        return Verify.Analyzer<InjectionAnalyzer>("""
            using System.Net;
            using Microsoft.AspNetCore.Html;

            public class GreetingController : ControllerBase
            {
                public IActionResult Hello(string name) => Content({|SL007:"<h1>Hello " + name + "</h1>"|}, "text/html");

                public IActionResult Encoded(string name) =>
                    Content("<h1>Hello " + WebUtility.HtmlEncode(name) + "</h1>", "text/html");

                public IActionResult Plain(string name) => Content("Hello " + name);

                public IActionResult Json(string name) => Content("{\"name\":1}", "application/json");

                public HtmlString Badge(string label) => new HtmlString({|SL007:$"<span>{label}</span>"|});
            }
            """);
    }

    // ---------------------------------------------------------------- SL008 LDAP, SL009 XPath

    [Fact]
    public Task Ldap_injection()
    {
        return Verify.Analyzer<InjectionAnalyzer>("""
            using System.DirectoryServices;

            public class DirectoryController : ControllerBase
            {
                public IActionResult Find(string user)
                {
                    using var searcher = new DirectorySearcher();
                    searcher.Filter = {|SL008:"(&(objectClass=user)(sAMAccountName=" + user + "))"|};
                    using var second = new DirectorySearcher({|SL008:$"(mail={user})"|});
                    using var third = new DirectorySearcher("(mail=" + EscapeLdap(user) + ")");
                    return Ok();
                }

                private static string EscapeLdap(string value) =>
                    value.Replace("\\", "\\5c").Replace("*", "\\2a").Replace("(", "\\28").Replace(")", "\\29").Replace("\0", "\\00");
            }
            """);
    }

    [Fact]
    public Task XPath_injection()
    {
        return Verify.Analyzer<InjectionAnalyzer>("""
            using System.Xml;
            using System.Xml.Linq;
            using System.Xml.XPath;

            public class CatalogController : ControllerBase
            {
                public IActionResult Find(string user, string password, int id)
                {
                    var document = new XmlDocument();
                    var node = document.SelectSingleNode({|SL009:"//user[name='" + user + "' and password='" + password + "']"|});
                    var byId = document.SelectNodes("//user[@id=" + id + "]");
                    var linq = XDocument.Parse("<users/>").XPathSelectElements({|SL009:$"//user[name='{user}']"|});
                    return Ok();
                }
            }
            """);
    }

    // ---------------------------------------------------------------- SL010 regex

    [Fact]
    public Task Regex_from_request_data_without_timeout()
    {
        return Verify.Analyzer<InjectionAnalyzer>("""
            using System.Text.RegularExpressions;

            public class SearchController : ControllerBase
            {
                public IActionResult Search(string pattern, string text)
                {
                    var a = Regex.IsMatch("some text", {|SL010:pattern|});
                    var b = new Regex({|SL010:"^" + pattern|});
                    // request data as the input of a fixed pattern is fine
                    var c = Regex.IsMatch(text, "^[a-z]+$");
                    var d = Regex.IsMatch("some text", pattern, RegexOptions.None, TimeSpan.FromMilliseconds(200));
                    var e = Regex.IsMatch("some text", pattern, RegexOptions.NonBacktracking);
                    var f = Regex.IsMatch("some text", Regex.Escape(pattern));
                    return Ok();
                }
            }
            """);
    }

    // ---------------------------------------------------------------- engine details

    [Fact]
    public Task Taint_flows_through_patterns_loops_local_functions_and_collections()
    {
        return Verify.Analyzer<InjectionAnalyzer>("""
            using System.Diagnostics;

            public class EngineController : ControllerBase
            {
                public IActionResult Run(object input, string[] hosts, string single)
                {
                    if (input is string text) Process.Start("tool", {|SL003:text|});

                    foreach (var host in hosts) Process.Start("ping", {|SL003:host|});

                    var arguments = new List<string>();
                    arguments.Add(single);
                    Process.Start("tool", {|SL003:string.Join(" ", arguments)|});

                    void Start(string value) => Process.Start("tool", {|SL003:value|});
                    Start(single);

                    var choice = single == "a" ? "--all" : "--none";
                    Process.Start("tool", choice);

                    var copy = single;
                    copy = "constant";
                    Process.Start("tool", {|SL003:copy|}); // flow-insensitive: one tainted assignment is enough
                    return Ok();
                }
            }
            """);
    }

    [Fact]
    public Task Hub_methods_are_entry_points()
    {
        return Verify.Analyzer<InjectionAnalyzer>("""
            using Microsoft.AspNetCore.SignalR;

            public class ChatHub : Hub
            {
                public Task Export(string room) =>
                    File.WriteAllTextAsync({|SL004:"exports/" + room + ".txt"|}, "exported");
            }
            """);
    }

    [Fact]
    public Task Virtual_methods_resolve_to_overrides()
    {
        return Verify.Analyzer<InjectionAnalyzer>("""
            public abstract class Storage
            {
                public abstract string Read(string name);
            }

            public class DiskStorage : Storage
            {
                public override string Read(string name) => File.ReadAllText({|SL004:"/data/" + name|});
            }

            public class DocsController : ControllerBase
            {
                private readonly Storage _storage;
                public DocsController(Storage storage) => _storage = storage;
                public IActionResult Get(string name) => Ok(_storage.Read(name));
            }
            """);
    }

    [Fact]
    public Task A_sanitizer_on_the_way_is_remembered_across_calls()
    {
        return Verify.Analyzer<InjectionAnalyzer>("""
            public class DiskStorage
            {
                public string Read(string name) => File.ReadAllText("/data/" + name);
            }

            public class DocsController : ControllerBase
            {
                private readonly DiskStorage _storage = new();
                public IActionResult Get(string name) => Ok(_storage.Read(Path.GetFileName(name)));
            }
            """);
    }

    [Fact]
    public Task Code_without_web_entry_points_is_quiet()
    {
        return Verify.Analyzer<InjectionAnalyzer>("""
            using System.Diagnostics;

            public class Tool
            {
                public void Run(string file, string url, string pattern)
                {
                    File.ReadAllText(file);
                    Process.Start("git", "add " + file);
                    new HttpClient().GetStringAsync(url);
                    System.Text.RegularExpressions.Regex.IsMatch("x", pattern);
                }
            }
            """);
    }
}
