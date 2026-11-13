using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Schlosser.Tests;

public class SecretsTests
{
    [Fact]
    public Task Literals_stored_under_secret_names()
    {
        return Verify.Analyzer<SecretsAnalyzer>("""
            using System.Net;

            public class Settings
            {
                private const string AdminPassword = {|SL030:"Winter2026!"|};
                public string ApiKey { get; set; } = {|SL030:"9f8b2c41d7e04a6fb1c3"|};

                public void Run(Microsoft.Extensions.Configuration.IConfiguration configuration)
                {
                    var clientSecret = {|SL030:"s3cr3t-value-77"|};
                    var credential = new NetworkCredential("svc-backup", {|SL030:"hunter22"|});
                    var jwtKey = configuration["Jwt:Key"] ?? {|SL030:"dev-fallback-key-1234567890"|};
                    var options = new SmtpOptions { Password = {|SL030:"mailpass1"|} };
                }
            }

            public class SmtpOptions { public string Password { get; set; } = ""; }
            """);
    }

    [Fact]
    public Task Names_of_secrets_are_not_secrets()
    {
        return Verify.Analyzer<SecretsAnalyzer>("""
            public class Settings
            {
                private const string PasswordHeader = "X-Password";
                private const string ApiKeyHeaderName = "X-Api-Key";
                private const string TokenType = "Bearer";
                public string Password { get; set; } = "";
                public string? Secret { get; set; } = null;

                public void Run(Microsoft.Extensions.Configuration.IConfiguration configuration, CancellationToken cancellationToken)
                {
                    var password = configuration["Smtp:Password"];
                    var apiKey = Environment.GetEnvironmentVariable("PAYMENT_API_KEY");
                    var secret = "Jwt:SigningKey";               // a configuration key
                    var token = "access_token";                  // a form field name
                    var passwordPlaceholder = "<your password>";
                    var clientSecret = "CHANGE_ME";              // placeholder
                    var passwordPrompt = "Please enter your password";
                    var apiKey2 = "your-api-key-here";
                    var pageToken = "abc123def456";              // a paging token is not a secret
                    var passwordError = "Password1 is too weak";
                }
            }
            """);
    }

    [Fact]
    public Task Known_credential_formats_are_found_under_any_name()
    {
        // The AWS value is the example key from the AWS documentation
        return Verify.Analyzer<SecretsAnalyzer>("""
            public class Deploy
            {
                private const string Region = "eu-central-1";
                private const string Id = {|SL030:"AKIAIOSFODNN7EXAMPLE"|};
                private const string Pem = {|SL030:"-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----"|};
                private const string Storage = {|SL030:"DefaultEndpointsProtocol=https;AccountName=demo;AccountKey=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV0123456789+/==;EndpointSuffix=core.windows.net"|};
            }
            """);
    }

    [Fact]
    public Task Connection_strings_and_urls_with_passwords()
    {
        return Verify.Analyzer<SecretsAnalyzer>("""
            public class Data
            {
                private const string Bad = {|SL030:"Server=db01;Database=Shop;User Id=sa;Password=Sommer2026!;"|};
                private const string AlsoBad = {|SL030:"Host=db;Username=app;Pwd=geheim123"|};
                private const string Amqp = {|SL030:"amqp://shop:rabbitpw@queue.internal:5672/"|};

                private const string Integrated = "Server=db01;Database=Shop;Integrated Security=true;";
                private const string Template = "Server=db01;Database=Shop;User Id=sa;Password={0};";
                private const string Placeholder = "Server=db01;User Id=sa;Password=<password>;";
                private const string Sqlite = "Data Source=app.db";
                private const string PlainUrl = "https://example.org/a:b@c";
                private const string Label = "Password=";
            }
            """);
    }

    [Fact]
    public async Task The_message_never_repeats_the_secret()
    {
        var diagnostics = await Verify.Diagnostics<SecretsAnalyzer>("""
            public class Settings { private const string AdminPassword = "Winter2026!"; }
            """);

        var message = Assert.Single(diagnostics).GetMessage();
        Assert.DoesNotContain("Winter2026", message);
        Assert.Contains("'AdminPassword'", message);
    }

    [Fact]
    public async Task Test_projects_only_report_real_credential_formats()
    {
        const string source = """
            public class LoginTests
            {
                private const string Password = "Winter2026!";
                private const string Leaked = "AKIAIOSFODNN7EXAMPLE";
            }
            """;

        // A compilation that references xunit, like a test project does
        var compilation = Verify.Compile(source)
            .AddReferences(MetadataReference.CreateFromFile(typeof(FactAttribute).Assembly.Location));
        var diagnostics = await compilation
            .WithAnalyzers(ImmutableArray.Create<DiagnosticAnalyzer>(new SecretsAnalyzer()))
            .GetAnalyzerDiagnosticsAsync();

        var diagnostic = Assert.Single(diagnostics);
        Assert.Contains("AWS access key id", diagnostic.GetMessage());
    }
}
