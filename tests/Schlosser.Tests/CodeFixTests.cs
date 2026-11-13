using Schlosser.CodeFixes;

namespace Schlosser.Tests;

public class CodeFixTests
{
    [Fact]
    public Task Raw_sql_becomes_interpolated_sql_and_loses_the_quotes()
    {
        const string model = """
            using Microsoft.EntityFrameworkCore;

            public class User { public int Id { get; set; } public string Name { get; set; } = ""; public string City { get; set; } = ""; }
            public class AppDb : DbContext { public DbSet<User> Users => Set<User>(); }

            """;

        return Verify.CodeFix<InjectionAnalyzer, SchlosserCodeFixProvider>(model + """
            public class UsersController : ControllerBase
            {
                private readonly AppDb _db;
                public UsersController(AppDb db) => _db = db;

                public IActionResult Search(string name, string city)
                {
                    var users = _db.Users.FromSqlRaw($"SELECT * FROM Users WHERE Name = '{name}' AND City = '{city}' ORDER BY Id").ToList();
                    _db.Database.ExecuteSqlRaw($"UPDATE Users SET City = '{city}' WHERE Name = '{name}'");
                    return Ok(users);
                }
            }
            """, model + """
            public class UsersController : ControllerBase
            {
                private readonly AppDb _db;
                public UsersController(AppDb db) => _db = db;

                public IActionResult Search(string name, string city)
                {
                    var users = _db.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Name = {name} AND City = {city} ORDER BY Id").ToList();
                    _db.Database.ExecuteSqlInterpolated($"UPDATE Users SET City = {city} WHERE Name = {name}");
                    return Ok(users);
                }
            }
            """);
    }

    [Fact]
    public Task Redirect_becomes_local_redirect()
    {
        return Verify.CodeFix<InjectionAnalyzer, SchlosserCodeFixProvider>("""
            public class AccountController : ControllerBase
            {
                public IActionResult Login(string returnUrl) => Redirect(returnUrl);
                public IActionResult Moved(string returnUrl) => this.RedirectPermanent(returnUrl ?? "/");
            }

            public static class Endpoints
            {
                public static void Map(WebApplication app) => app.MapGet("/go", (string to) => Results.Redirect(to));
            }
            """, """
            public class AccountController : ControllerBase
            {
                public IActionResult Login(string returnUrl) => LocalRedirect(returnUrl);
                public IActionResult Moved(string returnUrl) => this.LocalRedirectPermanent(returnUrl ?? "/");
            }

            public static class Endpoints
            {
                public static void Map(WebApplication app) => app.MapGet("/go", (string to) => Results.LocalRedirect(to));
            }
            """);
    }

    [Fact]
    public Task Weak_hash_becomes_sha256()
    {
        return Verify.CodeFix<CryptoAnalyzer, SchlosserCodeFixProvider>("""
            using System.Security.Cryptography;

            public class Hashes
            {
                public byte[] A(byte[] data) => MD5.HashData(data);
                public HashAlgorithm B() => SHA1.Create();
                public byte[] C(byte[] data, RSA rsa) => rsa.SignData(data, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
                public HMAC D(byte[] key) => new HMACMD5(key);
            }
            """, """
            using System.Security.Cryptography;

            public class Hashes
            {
                public byte[] A(byte[] data) => SHA256.HashData(data);
                public HashAlgorithm B() => SHA256.Create();
                public byte[] C(byte[] data, RSA rsa) => rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                public HMAC D(byte[] key) => new HMACSHA256(key);
            }
            """);
    }

    [Fact]
    public Task Random_becomes_random_number_generator_and_adds_the_using()
    {
        return Verify.CodeFix<CryptoAnalyzer, SchlosserCodeFixProvider>("""
            public class Codes
            {
                private readonly Random _random = new();

                public int NewOtp() => _random.Next(100000, 1000000);

                public byte[] NewToken()
                {
                    var token = new byte[32];
                    _random.NextBytes(token);
                    return token;
                }
            }
            """, """
            using System.Security.Cryptography;

            public class Codes
            {
                private readonly Random _random = new();

                public int NewOtp() => RandomNumberGenerator.GetInt32(100000, 1000000);

                public byte[] NewToken()
                {
                    var token = new byte[32];
                    RandomNumberGenerator.Fill(token);
                    return token;
                }
            }
            """);
    }

    [Fact]
    public Task Comparison_becomes_fixed_time_equals()
    {
        return Verify.CodeFix<CryptoAnalyzer, SchlosserCodeFixProvider>("""
            using System.Security.Cryptography;
            using System.Text;

            public class Webhook
            {
                public bool Bytes(byte[] expectedMac, byte[] providedMac) => expectedMac.SequenceEqual(providedMac);
                public bool Text(string expectedSignature, string header) => expectedSignature == header;
                public bool Different(string apiKey, string provided) => apiKey != provided;
            }
            """, """
            using System.Security.Cryptography;
            using System.Text;

            public class Webhook
            {
                public bool Bytes(byte[] expectedMac, byte[] providedMac) => CryptographicOperations.FixedTimeEquals(expectedMac, providedMac);
                public bool Text(string expectedSignature, string header) => CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(expectedSignature), Encoding.UTF8.GetBytes(header));
                public bool Different(string apiKey, string provided) => !CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(apiKey), Encoding.UTF8.GetBytes(provided));
            }
            """);
    }

    [Fact]
    public Task Xml_settings_become_safe()
    {
        return Verify.CodeFix<ConfigurationAnalyzer, SchlosserCodeFixProvider>("""
            using System.Xml;

            public class XmlParsing
            {
                public XmlReaderSettings Create() => new() { DtdProcessing = DtdProcessing.Parse, XmlResolver = new XmlUrlResolver() };
            }
            """, """
            using System.Xml;

            public class XmlParsing
            {
                public XmlReaderSettings Create() => new() { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
            }
            """);
    }

    [Fact]
    public Task Token_checks_are_switched_back_on()
    {
        return Verify.CodeFix<ConfigurationAnalyzer, SchlosserCodeFixProvider>("""
            using Microsoft.IdentityModel.Tokens;

            public class Auth
            {
                public TokenValidationParameters Create() => new() { ValidateIssuer = false, ValidateLifetime = false };
            }
            """, """
            using Microsoft.IdentityModel.Tokens;

            public class Auth
            {
                public TokenValidationParameters Create() => new() { ValidateIssuer = true, ValidateLifetime = true };
            }
            """);
    }

    [Fact]
    public Task Cookie_flags_are_added()
    {
        return Verify.CodeFix<ConfigurationAnalyzer, SchlosserCodeFixProvider>("""
            public class Cookies : ControllerBase
            {
                public void Set(string value)
                {
                    Response.Cookies.Append("a", value, new CookieOptions());
                    Response.Cookies.Append("b", value, new CookieOptions { HttpOnly = true, SameSite = SameSiteMode.Lax });
                    Response.Cookies.Append("c", value, new CookieOptions { HttpOnly = true, Secure = false });
                }
            }
            """, """
            public class Cookies : ControllerBase
            {
                public void Set(string value)
                {
                    Response.Cookies.Append("a", value, new CookieOptions() { Secure = true, HttpOnly = true });
                    Response.Cookies.Append("b", value, new CookieOptions { HttpOnly = true, SameSite = SameSiteMode.Lax, Secure = true });
                    Response.Cookies.Append("c", value, new CookieOptions { HttpOnly = true, Secure = true });
                }
            }
            """);
    }

    [Fact]
    public Task Lockout_is_switched_on()
    {
        return Verify.CodeFix<ConfigurationAnalyzer, SchlosserCodeFixProvider>("""
            using Microsoft.AspNetCore.Identity;

            public class Login
            {
                public Task SignIn(SignInManager<IdentityUser> signIn, string name, string password) =>
                    signIn.PasswordSignInAsync(name, password, isPersistent: false, lockoutOnFailure: false);
            }
            """, """
            using Microsoft.AspNetCore.Identity;

            public class Login
            {
                public Task SignIn(SignInManager<IdentityUser> signIn, string name, string password) =>
                    signIn.PasswordSignInAsync(name, password, isPersistent: false, lockoutOnFailure: true);
            }
            """);
    }

    [Fact]
    public async Task No_fix_is_offered_where_the_developer_has_to_decide()
    {
        // Response.Redirect has no local variant; concatenated SQL needs real parameters
        var fix = new SchlosserCodeFixProvider();
        Assert.DoesNotContain("SL003", fix.FixableDiagnosticIds);
        Assert.DoesNotContain("SL030", fix.FixableDiagnosticIds);
        Assert.DoesNotContain("SL031", fix.FixableDiagnosticIds);
        await Task.CompletedTask;
    }
}
