namespace Schlosser.Tests;

public class ConfigurationTests
{
    [Fact]
    public Task Certificate_validation_switched_off()
    {
        return Verify.Analyzer<ConfigurationAnalyzer>("""
            using System.Net;
            using System.Net.Security;

            public class Clients
            {
                public void Run(Stream stream)
                {
                    var a = new HttpClientHandler { ServerCertificateCustomValidationCallback = {|SL031:(message, certificate, chain, errors) => true|} };
                    var b = new HttpClientHandler();
                    b.ServerCertificateCustomValidationCallback = {|SL031:HttpClientHandler.DangerousAcceptAnyServerCertificateValidator|};
                    var c = new SslStream(stream, false, {|SL031:(sender, certificate, chain, errors) => { return true; }|});
            #pragma warning disable SYSLIB0014
                    ServicePointManager.ServerCertificateValidationCallback += {|SL031:delegate { return true; }|};
            #pragma warning restore SYSLIB0014

                    // a real decision is not reported
                    var d = new HttpClientHandler { ServerCertificateCustomValidationCallback = (message, certificate, chain, errors) => errors == SslPolicyErrors.None };
                    var e = new HttpClientHandler
                    {
                        ServerCertificateCustomValidationCallback = (message, certificate, chain, errors) =>
                        {
                            if (errors == SslPolicyErrors.None) return true;
                            return certificate?.Thumbprint == "AB12";
                        },
                    };
                    Func<int, bool> unrelated = _ => true;
                }
            }
            """);
    }

    [Fact]
    public Task Old_tls_versions()
    {
        return Verify.Analyzer<ConfigurationAnalyzer>("""
            using System.Net;
            using System.Security.Authentication;

            public class Tls
            {
                public void Run(HttpClientHandler handler)
                {
            #pragma warning disable SYSLIB0014, SYSLIB0039, CS0618
                    handler.SslProtocols = {|SL032:SslProtocols.Tls|} | {|SL032:SslProtocols.Tls11|} | SslProtocols.Tls12;
                    ServicePointManager.SecurityProtocol = {|SL032:SecurityProtocolType.Ssl3|};
            #pragma warning restore SYSLIB0014, SYSLIB0039, CS0618
                    handler.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
                    handler.SslProtocols = SslProtocols.None;
                }
            }
            """);
    }

    [Fact]
    public Task Insecure_deserialization()
    {
        return Verify.Analyzer<ConfigurationAnalyzer>("""
            using Newtonsoft.Json;
            using Newtonsoft.Json.Serialization;

            public class Serializers
            {
                public void Run(string json)
                {
                    var bad = new JsonSerializerSettings { {|SL033:TypeNameHandling = TypeNameHandling.All|} };
                    var alsoBad = new JsonSerializerSettings();
                    {|SL033:alsoBad.TypeNameHandling = TypeNameHandling.Auto|};

                    var withBinder = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.Objects, SerializationBinder = new DefaultSerializationBinder() };
                    var none = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.None };
                    var plain = JsonConvert.DeserializeObject<Dictionary<string, string>>(json);
                    var systemTextJson = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(json);
                }
            }
            """);
    }

    [Fact]
    public Task Xml_external_entities()
    {
        return Verify.Analyzer<ConfigurationAnalyzer>("""
            using System.Xml;

            public class XmlParsing
            {
                public void Run(Stream input)
                {
                    var bad = new XmlReaderSettings { {|SL034:DtdProcessing = DtdProcessing.Parse|}, {|SL034:XmlResolver = new XmlUrlResolver()|} };
                    var document = new XmlDocument();
                    {|SL034:document.XmlResolver = new XmlUrlResolver()|};

                    var good = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
                    var ignore = new XmlReaderSettings { DtdProcessing = DtdProcessing.Ignore };
                    var safeDocument = new XmlDocument { XmlResolver = null };
                    using var reader = XmlReader.Create(input, good);
                }
            }
            """);
    }

    [Fact]
    public Task Token_validation_switched_off()
    {
        return Verify.Analyzer<ConfigurationAnalyzer>("""
            using Microsoft.AspNetCore.Authentication.JwtBearer;
            using Microsoft.IdentityModel.Tokens;

            public class Auth
            {
                public void Configure(JwtBearerOptions options)
                {
                    {|SL035:options.RequireHttpsMetadata = false|};
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        {|SL035:ValidateIssuer = false|},
                        {|SL035:ValidateAudience = false|},
                        {|SL035:ValidateLifetime = false|},
                        {|SL035:RequireSignedTokens = false|},
                        {|SL035:SignatureValidator = (token, parameters) => new Microsoft.IdentityModel.JsonWebTokens.JsonWebToken(token)|},
                    };
                }

                public void Good(JwtBearerOptions options)
                {
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidIssuer = "https://login.example.org",
                        ValidateAudience = true,
                        ValidAudience = "orders-api",
                        ValidateLifetime = true,
                        ClockSkew = TimeSpan.FromSeconds(30),
                    };
                }
            }
            """);
    }

    [Fact]
    public async Task Token_message_explains_the_consequence()
    {
        var diagnostics = await Verify.Diagnostics<ConfigurationAnalyzer>("""
            using Microsoft.IdentityModel.Tokens;

            public class Auth
            {
                public TokenValidationParameters Create() => new() { ValidateLifetime = false };
            }
            """);

        Assert.Equal("ValidateLifetime = false switches off a check of the token: expired tokens are accepted forever.",
            Assert.Single(diagnostics).GetMessage());
    }

    [Fact]
    public Task Cookie_flags()
    {
        return Verify.Analyzer<ConfigurationAnalyzer>("""
            using Microsoft.AspNetCore.Authentication.Cookies;

            public class Cookies : ControllerBase
            {
                public void Set(string value, IWebHostEnvironmentLike environment)
                {
                    {|SL036:Response.Cookies.Append("session", value)|};
                    Response.Cookies.Append("a", value, {|SL036:new CookieOptions()|});
                    Response.Cookies.Append("b", value, {|SL036:new CookieOptions { HttpOnly = true }|});
                    Response.Cookies.Append("c", value, {|SL036:new CookieOptions { Secure = true, Expires = DateTimeOffset.UtcNow.AddDays(1) }|});
                    Response.Cookies.Append("d", value, new CookieOptions { HttpOnly = true, {|SL036:Secure = false|} });

                    Response.Cookies.Append("ok1", value, new CookieOptions { Secure = true, HttpOnly = true, SameSite = SameSiteMode.Strict });
                    Response.Cookies.Append("ok2", value, new CookieOptions { Secure = Request.IsHttps, HttpOnly = true });
                }

                public void SetLater(string value)
                {
                    var options = new CookieOptions();
                    options.Secure = true;
                    options.HttpOnly = true;
                    Response.Cookies.Append("ok3", value, options);
                }

                public void Configure(CookieAuthenticationOptions options)
                {
                    {|SL036:options.Cookie.HttpOnly = false|};
                    {|SL036:options.Cookie.SecurePolicy = CookieSecurePolicy.None|};
                    options.Cookie.SameSite = SameSiteMode.Lax;
                }
            }

            public interface IWebHostEnvironmentLike { }
            """);
    }

    [Fact]
    public Task Cors_any_origin_with_credentials()
    {
        return Verify.Analyzer<ConfigurationAnalyzer>("""
            using Microsoft.AspNetCore.Cors.Infrastructure;
            using Microsoft.Extensions.DependencyInjection;

            public static class Startup
            {
                public static void Configure(IServiceCollection services)
                {
                    services.AddCors(options =>
                    {
                        options.AddPolicy("bad", policy => policy.{|SL037:SetIsOriginAllowed|}(_ => true).AllowAnyHeader().AllowCredentials());
                        options.AddPolicy("public", policy => policy.AllowAnyOrigin().AllowAnyHeader());
                        options.AddPolicy("reflect", policy => policy.SetIsOriginAllowed(_ => true).AllowAnyHeader());
                        options.AddPolicy("good", policy => policy.WithOrigins("https://app.example.org").AllowCredentials());
                        options.AddPolicy("checked", policy => policy.SetIsOriginAllowed(origin => origin.EndsWith(".example.org")).AllowCredentials());
                    });
                }

                public static void Manual(HttpContext context)
                {
                    {|SL037:context.Response.Headers["Access-Control-Allow-Origin"] = context.Request.Headers["Origin"]|};
                    context.Response.Headers["Access-Control-Allow-Credentials"] = "true";
                }

                public static void ManualFixed(HttpContext context) =>
                    context.Response.Headers["Access-Control-Allow-Origin"] = "https://app.example.org";
            }
            """);
    }

    [Fact]
    public Task Anti_forgery_switched_off()
    {
        return Verify.Analyzer<ConfigurationAnalyzer>("""
            using Microsoft.AspNetCore.Mvc.RazorPages;

            [{|SL038:IgnoreAntiforgeryToken|}]
            public class TransferModel : PageModel
            {
                public void OnPost() { }
            }

            public class PaymentsController : Controller
            {
                [HttpPost, {|SL038:IgnoreAntiforgeryToken|}]
                public IActionResult Pay() => Ok();

                [HttpPost, ValidateAntiForgeryToken]
                public IActionResult Refund() => Ok();
            }

            public static class Endpoints
            {
                public static void Map(WebApplication app)
                {
                    app.MapPost("/upload", (IFormFile file) => Results.Ok()).{|SL038:DisableAntiforgery|}();
                    app.MapPost("/form", (IFormFile file) => Results.Ok());
                    // validates the token itself
                    app.MapPost("/logout", async (HttpContext context, Microsoft.AspNetCore.Antiforgery.IAntiforgery antiforgery) =>
                        await antiforgery.IsRequestValidAsync(context) ? Results.Ok() : Results.BadRequest()).DisableAntiforgery();
                }
            }
            """);
    }

    [Fact]
    public Task Secrets_in_logs()
    {
        return Verify.Analyzer<ConfigurationAnalyzer>("""
            public class LoginRequest { public string Username { get; set; } = ""; public string Password { get; set; } = ""; }

            public class Login
            {
                private readonly ILogger<Login> _logger;
                public Login(ILogger<Login> logger) => _logger = logger;

                public void Run(LoginRequest request, string apiKey, string refreshToken, string passwordHash, int tokenCount)
                {
                    _logger.LogInformation("Login {User} with {Password}", request.Username, {|SL039:request.Password|});
                    _logger.LogWarning($"Key rejected: {{|SL039:apiKey|}}");
                    _logger.LogDebug("Refresh " + {|SL039:refreshToken|});
                    _logger.LogError(new InvalidOperationException(), "Failed for {Token}", {|SL039:refreshToken|});

                    _logger.LogInformation("Login {User}", request.Username);
                    _logger.LogInformation("Password length {Length}", request.Password.Length);
                    _logger.LogInformation("Password set: {HasPassword}", request.Password != null);
                    _logger.LogInformation("{Count} tokens revoked", tokenCount);
                    _logger.LogInformation("Password reset requested for {User}", request.Username);
                }
            }
            """);
    }

    [Fact]
    public Task Exception_details_in_responses()
    {
        return Verify.Analyzer<ConfigurationAnalyzer>("""
            public class DomainException : Exception { public DomainException(string message) : base(message) { } }

            public class OrdersController : ControllerBase
            {
                public IActionResult Get(int id)
                {
                    try
                    {
                        return Ok(id);
                    }
                    catch (DomainException ex)
                    {
                        return BadRequest(ex.Message); // written for the user
                    }
                    catch (InvalidOperationException ex)
                    {
                        return StatusCode(500, {|SL040:ex.ToString()|});
                    }
                    catch (Exception ex)
                    {
                        if (id == 1) return Problem(detail: {|SL040:ex.StackTrace|});
                        if (id == 2) return BadRequest({|SL040:ex.Message|});
                        if (id == 3) return StatusCode(500, {|SL040:ex|});
                        return StatusCode(500, "Something went wrong.");
                    }
                }
            }

            public static class Startup
            {
                public static void Configure(WebApplication app)
                {
                    app.{|SL040:UseDeveloperExceptionPage|}();
                }

                public static void ConfigureChecked(WebApplication app)
                {
                    if (Microsoft.Extensions.Hosting.HostEnvironmentEnvExtensions.IsDevelopment(app.Environment)) app.UseDeveloperExceptionPage();
                }
            }
            """);
    }

    [Fact]
    public Task Identity_password_policy_and_lockout()
    {
        return Verify.Analyzer<ConfigurationAnalyzer>("""
            using Microsoft.AspNetCore.Identity;

            public class Identity
            {
                public void Configure(IdentityOptions options)
                {
                    {|SL041:options.Password.RequiredLength = 4|};
                    {|SL042:options.Lockout.AllowedForNewUsers = false|};
                    // NIST: length matters, character classes do not
                    options.Password.RequireDigit = false;
                    options.Password.RequireNonAlphanumeric = false;
                    options.Lockout.MaxFailedAccessAttempts = 5;
                }

                public void Good(IdentityOptions options) => options.Password.RequiredLength = 12;

                public async Task SignIn(SignInManager<IdentityUser> signIn, IdentityUser user, string name, string password)
                {
                    await signIn.PasswordSignInAsync(name, password, isPersistent: false, lockoutOnFailure: {|SL042:false|});
                    await signIn.CheckPasswordSignInAsync(user, password, {|SL042:false|});
                    await signIn.PasswordSignInAsync(name, password, false, lockoutOnFailure: true);
                }
            }
            """);
    }
}
