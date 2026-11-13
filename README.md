# Schlosser

Security analyzers for C# and ASP.NET Core. *Schlosser* is German for locksmith.

Schlosser runs inside the compiler. It follows data from the HTTP request to the places where it becomes dangerous
(SQL text, shell commands, file paths, redirects, outgoing requests, raw HTML) and it does so **across methods, classes and
interfaces**. It also finds weak cryptography, hard-coded secrets and protections that were switched off. For nine rules it
offers a code fix.

```
Data/OrderRepository.cs(49,39): warning SL001: SQL injection: parameter 'model' of CheckoutController.Checkout
  flows into DbCommand.CommandText (call path: CheckoutController.Checkout → OrderRepository.CreateOrder).
  Pass the value as a parameter instead of building the SQL text.
```

That is a real finding in [OWASP WebGoat.NET](https://github.com/tobyash86/WebGoat.NET): the controller looks harmless, the
SQL is built one class away. A check that only looks at one method cannot see it.

- **31 rules** with CWE ids: [docs/rules.md](docs/rules.md)
- **Taint analysis** from controllers, Razor Pages, minimal APIs and SignalR hubs into 9 kinds of dangerous calls
- **Type-aware**: an `int`, `Guid` or `DateTime` from the request cannot carry SQL and is not reported
- **Code fixes**: `FromSqlRaw($"…'{x}'")` → `FromSqlInterpolated($"…{x}")`, `Redirect` → `LocalRedirect`, MD5 → SHA-256,
  `Random` → `RandomNumberGenerator`, `==` → `FixedTimeEquals`, XML, JWT, cookie and lockout settings
- **SARIF** for GitHub Code Scanning comes from the compiler, no extra tool
- 82 tests; checked in CI against a sample app and against WebGoat.NET at a pinned commit

## Use it

The package is not on nuget.org yet. Build it (or take `schlosser-nupkg` from a CI run) and add the folder as a source:

```
dotnet pack src/Schlosser.Analyzers -c Release -o nupkg
dotnet add package Schlosser.Analyzers --version 1.0.0 --source ./nupkg
```

```xml
<PackageReference Include="Schlosser.Analyzers" Version="1.0.0" PrivateAssets="all" />
```

The findings appear as warnings in `dotnet build` and in the IDE. To write SARIF and to fail the build on findings:

```
dotnet build -p:ErrorLog=schlosser.sarif,version=2.1 -warnaserror:SL001,SL003,SL004
```

Rules are configured like every other analyzer, in `.editorconfig`:

```ini
dotnet_diagnostic.SL002.severity = warning   # also show SQL built from strings without a proven request path
dotnet_diagnostic.SL039.severity = error     # a secret in the log breaks the build
dotnet_diagnostic.SL036.severity = none      # cookie flags are set globally by CookiePolicyOptions
```

A single place is suppressed with a reason, which is what an auditor wants to read:

```csharp
#pragma warning disable SL031 // This scanner inspects certificates of other sites, so it must accept broken ones too
```

## What it finds

| Group | Rules |
|---|---|
| Injection, followed from the request | SL001 SQL injection · SL002 SQL built from strings · SL003 command injection · SL004 path traversal · SL005 open redirect · SL006 server-side request forgery · SL007 cross-site scripting · SL008 LDAP injection · SL009 XPath injection · SL010 regular expression denial of service |
| Web | SL011 mass assignment (entity bound from the request) · SL012 `Html.Raw` in Razor views · SL036 cookie flags · SL037 CORS with credentials for every origin · SL038 anti-forgery switched off · SL040 exception details in responses |
| Cryptography | SL020 MD5 / SHA-1 · SL021 DES, 3DES, RC2, ECB · SL022 `System.Random` for secrets · SL023 hard-coded key, IV, salt · SL024 weak password hashing · SL025 secret compared in non-constant time |
| Secrets and configuration | SL030 hard-coded secret · SL031 certificate validation disabled · SL032 SSL 3 / TLS 1.0 / 1.1 · SL033 insecure deserialization · SL034 XML external entities · SL035 token validation switched off · SL039 secret written to the log · SL041 short passwords allowed · SL042 no lockout |

## How the taint analysis works

**Sources.** Parameters of controller actions, Razor Page handlers, SignalR hub methods and minimal API handlers (lambdas and
method groups), properties with `[BindProperty]` or `[FromQuery]`, and everything read from `HttpRequest`.
Services are not sources: `[FromServices]`, interfaces, `DbContext`, and in minimal APIs classes without settable properties.

**Inside a method** the analysis is flow-insensitive: a variable is tainted if any assignment to it is tainted. Taint passes
through concatenation, interpolation, `string.Format`, `StringBuilder`, collections, string methods, pattern matching,
loops and local functions. It stops at types that cannot carry text (numbers, dates, GUIDs, enums) and at a choice between
constants (`sort == "price" ? "Price" : "Name"`), which is the allow-list pattern.

**Across methods** it works with summaries, in one pass over the compilation:

1. While a method is analyzed, its parameters are treated as symbols. Every parameter that reaches a dangerous call is
   recorded (`UserRepository.Find, parameter 0 → SQL`), and so is every call that passes request data or a parameter on.
2. At the end the lists are joined: request data → call → parameter → … → dangerous call, up to 8 calls deep.
3. Calls through interfaces and virtual methods are resolved to the implementations in the same compilation.

The message names the entry point and the call path; the call in the controller is attached as a second location.

**Sanitizers** are specific to the kind of sink. `Path.GetFileName` makes a value safe for file paths but not for SQL;
`HtmlEncode` helps against cross-site scripting only. A sanitizer on the way is remembered across calls. For SQL and
shell commands nothing counts as a sanitizer: only parameters and allow-lists are a fix.

**Precision details** that keep the output short:

- Server-side request forgery is only reported when the request decides the *host*. `"https://api.example.org/rates/" + currency`
  and relative addresses are fine, `"https://" + tenant + ".example.org"` is not.
- `Redirect` after `Url.IsLocalUrl`, and file access after `Path.GetFullPath` plus `StartsWith`, are treated as checked.
- A comparison inside a LINQ query (`db.Sessions.Where(s => s.Token == token)`) runs in the database and is no timing issue.
- HMAC-SHA1 is not reported: it is sound and required by TOTP.
- The names of secrets are not secrets: `"Jwt:SigningKey"`, `"X-Api-Key"`, `"access_token"` and `<your password>` are ignored.
- SL030 never repeats the secret in its message, so it does not spread into build logs and SARIF files.

## Checked against code I did not write

`tools/webgoat-contract.sh` attaches the analyzer to the unmodified **OWASP WebGoat.NET** at a pinned commit and compares
the result with a reviewed list ([tools/webgoat-expected.txt](tools/webgoat-expected.txt)). It runs in CI.

| Result | Findings |
|---|---|
| Real, as intended by WebGoat | SQL injection in the checkout (found through `CheckoutController → OrderRepository`), two open redirects, stored XSS in two views, approval code from `System.Random`, passwords of 2 characters, no lockout, session cookie readable by scripts, exception message shown to the user |
| Real, not on WebGoat's own list | mass assignment of the `Product` entity (2 places, admin area), `[IgnoreAntiforgeryToken]` on the error page |
| Over-approximation | the second SQL statement in `CreateOrder`: it is built from the same `order` object, but only from numbers and a tracking number the server generated. Schlosser tracks objects as a whole, not field by field. |

The first run found 9 of these 14. The missing five (views, password policy, lockout, the approval code) became the rules
SL012, SL041, SL042 and a fix in SL022. That is the reason to test against foreign code.

**My own projects.** I ran Schlosser over the 15 other repositories of my portfolio (about 38,000 lines of C#, tests included). First
run: 14 findings. Seven were false positives of three kinds, which I fixed in the analyzer (hashes of audit records are
public, so comparing them is not a timing leak; a handler that validates the anti-forgery token itself; one finding reported
under two rules). The remaining seven are deliberate: two certificate scanners that must accept invalid certificates to
inspect them (3), SHA-1 for the Have I Been Pwned range API (2), a test that creates a SHA-1 certificate on purpose, and an
ingest endpoint with API-key authentication instead of cookies.
SecureAuth API and Kontor (payments) come out clean.

## The sample

[samples/VulnerableShop](samples/VulnerableShop) is a small shop where every file in `Vulnerable/` has a twin in `Fixed/`
that does the same job safely. Building it gives 19 findings, all of them in `Vulnerable/`:

```
dotnet build samples/VulnerableShop
node tools/findings.mjs samples/VulnerableShop/obj/schlosser.sarif samples/VulnerableShop --all --check samples/VulnerableShop/expected-findings.txt
```

## Limits

Honest list, because a static analyzer that claims to find everything is lying:

- **Return values of your own methods** are tainted if any argument is tainted. The body of the callee is not used to
  refine that.
- **Objects are tainted as a whole.** After `order.Note = input`, every text property of `order` counts as tainted.
- **Fields and constructors** are not followed across methods: `new Service(input)` and a later `service.Run()` are not connected.
- **Stored data** is not tracked. What was saved to the database and is read back counts as clean, except in `Html.Raw` (SL012).
- **Guards are recognized by presence**, not by control flow: a call to `Url.IsLocalUrl` anywhere in the method counts.
- **One compilation at a time.** A controller in one project and the repository in another are analyzed separately;
  the repository then gets SL002 (SQL built from strings) instead of SL001.
- Cross-method results (SL001 to SL011) are computed at the end of the compilation. They appear in the build and in
  full-solution analysis, not while typing.

## Build

```
dotnet test                      # 82 tests
dotnet pack src/Schlosser.Analyzers -c Release -o nupkg
bash tools/webgoat-contract.sh   # needs git and network
```

The tests compile snippets against the real ASP.NET Core, EF Core, Dapper, Newtonsoft.Json and JwtBearer assemblies.
A marker `{|SL001:expression|}` says where a finding must be; a snippet with a compile error fails the test, so a typo can
never make a "nothing found" test pass. Code fix tests apply the fix until nothing is left and compile the result.

Layout: `src/Schlosser.Analyzers` (netstandard2.0, Roslyn 4.8, so it loads in Visual Studio 2022 17.8+ and every newer SDK),
`src/Schlosser.CodeFixes`, `tests/Schlosser.Tests`, `samples/VulnerableShop`, `tools/`.

MIT License.
