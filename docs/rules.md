# Rules

Every rule has a stable id, a CWE and a default severity. Change the severity in `.editorconfig`
(`dotnet_diagnostic.SL001.severity = error`), suppress a single place with `#pragma warning disable SL001 // reason`.

"Request data" means: parameters of controller actions, Razor Page handlers, SignalR hub methods and minimal API handlers,
bound properties, and everything read from `HttpRequest`. Rules marked **taint** follow that data through variables,
calls, interfaces and classes. Rules marked **fix** offer a code fix.

| Id | Rule | CWE | Severity | |
|---|---|---|---|---|
| [SL001](#sl001) | SQL injection | CWE-89 | warning | taint, fix |
| [SL002](#sl002) | SQL text is built from strings | CWE-89 | note | |
| [SL003](#sl003) | Command injection | CWE-78 | warning | taint |
| [SL004](#sl004) | Path traversal | CWE-22 | warning | taint |
| [SL005](#sl005) | Open redirect | CWE-601 | warning | taint, fix |
| [SL006](#sl006) | Server-side request forgery | CWE-918 | warning | taint |
| [SL007](#sl007) | Cross-site scripting | CWE-79 | warning | taint |
| [SL008](#sl008) | LDAP injection | CWE-90 | warning | taint |
| [SL009](#sl009) | XPath injection | CWE-643 | warning | taint |
| [SL010](#sl010) | Regular expression from request data | CWE-1333 | warning | taint |
| [SL011](#sl011) | Database entity bound from the request | CWE-915 | warning | |
| [SL012](#sl012) | Unencoded output in a Razor view | CWE-79 | warning | |
| [SL020](#sl020) | Broken hash algorithm | CWE-328 | warning | fix |
| [SL021](#sl021) | Weak cipher or cipher mode | CWE-327 | warning | |
| [SL022](#sl022) | Predictable random numbers for a secret | CWE-338 | warning | fix |
| [SL023](#sl023) | Hard-coded cryptographic key, IV or salt | CWE-321 | warning | |
| [SL024](#sl024) | Weak password hashing | CWE-916 | warning | |
| [SL025](#sl025) | Secret compared in non-constant time | CWE-208 | warning | fix |
| [SL030](#sl030) | Hard-coded secret | CWE-798 | warning | |
| [SL031](#sl031) | TLS certificate validation is disabled | CWE-295 | warning | |
| [SL032](#sl032) | Outdated TLS version | CWE-327 | warning | |
| [SL033](#sl033) | Insecure deserialization | CWE-502 | warning | |
| [SL034](#sl034) | XML external entities are enabled | CWE-611 | warning | fix |
| [SL035](#sl035) | Token validation is switched off | CWE-347 | warning | fix |
| [SL036](#sl036) | Cookie without protective flags | CWE-614 | warning | fix |
| [SL037](#sl037) | CORS allows every origin with credentials | CWE-942 | warning | |
| [SL038](#sl038) | Anti-forgery protection is switched off | CWE-352 | warning | |
| [SL039](#sl039) | Secret written to the log | CWE-532 | warning | |
| [SL040](#sl040) | Exception details sent to the client | CWE-209 | warning | |
| [SL041](#sl041) | Password policy allows very short passwords | CWE-521 | warning | |
| [SL042](#sl042) | Failed sign-ins are not limited | CWE-307 | warning | fix |

## Injection

### SL001

**SQL injection.** Request data becomes part of the SQL text of an ADO.NET command, an EF Core raw query
(`FromSqlRaw`, `ExecuteSqlRaw`, `SqlQueryRaw`) or a Dapper call.

```csharp
db.Users.FromSqlRaw($"SELECT * FROM Users WHERE Name = '{name}'");            // SL001
db.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Name = {name}");     // fine: {name} becomes a parameter
connection.Query<User>("SELECT * FROM Users WHERE Name = @name", new { name }); // fine
```

Numbers, dates, GUIDs and enums are not reported. A choice between constants is the correct fix for things that cannot be
parameters (`ORDER BY`, table names) and is not reported. The code fix rewrites EF Core raw calls with an interpolated
string and removes the quotes around the holes.

### SL002

**SQL text is built from strings.** The same pattern as SL001, but no path from request data was found in this
compilation: a library method, a background job, or a repository whose callers live in another project. Severity note,
so it shows up in SARIF and the IDE but not in the build output. Raise it if you want to review every such place.

### SL003

**Command injection.** Request data in `Process.Start` or `ProcessStartInfo` (`FileName`, `Arguments`).
Nothing counts as a sanitizer. Use a fixed program, `ArgumentList` instead of an argument string, and validate the value
into a type that cannot carry commands (`IPAddress.TryParse`, an enum, an allow-list).

### SL004

**Path traversal.** Request data in `File.*`, `Directory.*`, `FileStream`, `StreamReader`, `StreamWriter`, `FileInfo`,
`PhysicalFile`. The file name of an upload (`IFormFile.FileName`) is request data.

```csharp
File.ReadAllBytes(Path.Combine(root, name));                    // SL004: name can be ../../appsettings.json
File.ReadAllBytes(Path.Combine(root, Path.GetFileName(name)));  // fine
```

Also accepted: `Path.GetFullPath` followed by a `StartsWith` check against the base folder in the same method.

### SL005

**Open redirect.** Request data in `Redirect`, `RedirectPermanent`, `Response.Redirect`, `Results.Redirect`,
`new RedirectResult`. Fine after `Url.IsLocalUrl`, or with `LocalRedirect` (that is the code fix).

### SL006

**Server-side request forgery.** Request data decides the address of `HttpClient`, `HttpRequestMessage`, `WebRequest`
or `WebClient`. Only reported when the request controls the scheme or host:

```csharp
http.GetStringAsync(url);                                             // SL006
http.GetStringAsync("https://" + tenant + ".example.org/status");     // SL006
http.GetStringAsync("https://api.example.org/rates/" + currency);     // fine: fixed host
http.GetStringAsync($"api/users/{id}");                               // fine: relative to BaseAddress
```

### SL007

**Cross-site scripting.** Request data in `new HtmlString`, `Html.Raw` (in C# code), `new MarkupString`, or `Content(…, "text/html")`.
Fine after `WebUtility.HtmlEncode`, `HtmlEncoder.Encode` or `HttpUtility.HtmlEncode`. `Content(text)` without a content type is
`text/plain` and not reported.

### SL008

**LDAP injection.** Request data in `DirectorySearcher.Filter` or a `SearchRequest` filter. Escape the value for filters
(RFC 4515); a method of your own whose name starts with `Escape`, `Encode` or `Sanitize` is trusted here.

### SL009

**XPath injection.** Request data in `SelectNodes`, `SelectSingleNode`, `XPathSelectElements`, `XPathNavigator.Select`,
`XPathExpression.Compile`.

### SL010

**Regular expression from request data.** The pattern (not the input) comes from the request and there is no timeout.
Fine with `Regex.Escape`, a `matchTimeout` argument or `RegexOptions.NonBacktracking`.

## Web

### SL011

**Database entity bound from the request.** An action, page handler or minimal API handler takes a class that is a
`DbSet<T>` entity of a `DbContext` in the compilation. Model binding fills every property the client sends, so the
message names the ones an attacker would try first (`IsAdmin`, `Role`, `Balance`, `Price`). Bind a request model, or
use `[Bind("Title,Text")]`.

### SL012

**Unencoded output in a Razor view.** `@Html.Raw(value)` in a `.cshtml` file with anything that is not a constant,
`Json.Serialize`, `System.Text.Json`, `IHtmlContent` or a sanitizer call. There is no taint tracking here on purpose:
views print what is in the database, and stored cross-site scripting cannot be seen in the data flow of one request.
`JsonConvert.SerializeObject` stays reported because Newtonsoft.Json does not escape `<` by default.

### SL036

**Cookie without protective flags.** `new CookieOptions` without `Secure` and `HttpOnly`, `Cookies.Append` without
options, and explicit `HttpOnly = false`, `Secure = false`, `CookieSecurePolicy.None`. If the flags are enforced
globally with `CookiePolicyOptions`, switch this rule off.

### SL037

**CORS allows every origin with credentials.** `SetIsOriginAllowed(_ => true)` or `AllowAnyOrigin()` together with
`AllowCredentials()`, or the `Origin` request header copied into `Access-Control-Allow-Origin`. A public API without
credentials may allow every origin and is not reported.

### SL038

**Anti-forgery protection is switched off.** `[IgnoreAntiforgeryToken]` and `.DisableAntiforgery()`. Not reported when
the handler validates the token itself (`IAntiforgery.IsRequestValidAsync`). Correct for endpoints without cookie
authentication (webhooks, API keys): suppress it there with the reason.

### SL040

**Exception details sent to the client.** `ex.ToString()`, `ex.StackTrace` or the exception object in a response;
`ex.Message` only for `catch (Exception)`, because the message of a specific domain exception is usually written for the
user; `UseDeveloperExceptionPage()` outside of an `IsDevelopment()` check.

## Cryptography

### SL020

**Broken hash algorithm.** MD5 and SHA-1 (`Create`, `HashData`, the old provider classes, `HMACMD5`, and
`HashAlgorithmName.SHA1` in `SignData` / `VerifyData`). HMAC-SHA1 is not reported.

### SL021

**Weak cipher or cipher mode.** DES, Triple DES, RC2, `CipherMode.ECB`, `EncryptEcb`.

### SL022

**Predictable random numbers for a secret.** `System.Random` where the variable, method or type that receives the value
is named like a secret (`resetToken`, `NewPassword`, `otp`, `salt`, `sessionId`, `code` …). Jitter, sampling and test data
are not reported. Code fix: `RandomNumberGenerator.GetInt32` / `Fill`.

### SL023

**Hard-coded cryptographic key, IV or salt.** A byte array literal, `Encoding.GetBytes("literal")` or
`Convert.FromBase64String("literal")`, directly or through a local or field, used as `Key`, `IV`, HMAC key,
`SymmetricSecurityKey` or PBKDF2 salt. `new byte[16]` as an IV is an all-zero IV.

### SL024

**Weak password hashing.** A password under one round of a fast hash (`SHA256.HashData(Encoding.UTF8.GetBytes(password))`),
PBKDF2 with fewer than 100,000 iterations, with SHA-1, or `Rfc2898DeriveBytes` with its defaults (1,000 rounds of SHA-1).

### SL025

**Secret compared in non-constant time.** `==`, `string.Equals` or `SequenceEqual` on a value named like a signature,
MAC, token, API key, OTP or password hash. The hash of a file or audit record is public and not reported, and neither are
comparisons with constants or inside LINQ queries. Code fix: `CryptographicOperations.FixedTimeEquals`.

## Secrets and configuration

### SL030

**Hard-coded secret.** Three signals: a literal in the format of a real credential (AWS, GitHub, Slack, Stripe, Google,
SendGrid, Azure storage, JWT, private key); a connection string or URL with a password; a literal stored under a secret
name (`password`, `clientSecret`, `apiKey`, `accessToken`). Configuration keys, header names, placeholders and sentences
are ignored. In test projects only real credential formats are reported. The message never contains the secret.

### SL031

**TLS certificate validation is disabled.** A validation callback that always returns `true`, or
`DangerousAcceptAnyServerCertificateValidator`.

### SL032

**Outdated TLS version.** `SslProtocols.Ssl3`, `Tls`, `Tls11` and the same in `SecurityProtocolType`.

### SL033

**Insecure deserialization.** `BinaryFormatter`, `NetDataContractSerializer`, `SoapFormatter`, `LosFormatter`,
`ObjectStateFormatter`, and Newtonsoft.Json `TypeNameHandling` other than `None` without a `SerializationBinder`.

### SL034

**XML external entities are enabled.** `DtdProcessing.Parse`, `ProhibitDtd = false`, `XmlResolver = new XmlUrlResolver()`.
Code fix: `DtdProcessing.Prohibit`, `XmlResolver = null`.

### SL035

**Token validation is switched off.** `ValidateIssuer`, `ValidateAudience`, `ValidateLifetime`, `RequireSignedTokens`,
`RequireExpirationTime` set to `false`, `RequireHttpsMetadata = false`, or a custom `SignatureValidator`. The message says
what an attacker can do with each of them. `ValidateIssuerSigningKey = false` is not reported: it is the default and does
not skip the signature check.

### SL039

**Secret written to the log.** An argument of `ILogger`, Serilog, NLog or `Console.Write` whose name is a secret
(`password`, `apiKey`, `refreshToken`, `cardNumber`, `connectionString` …). `password.Length` and `password != null` are fine.

### SL041

**Password policy allows very short passwords.** ASP.NET Core Identity `RequiredLength` below 8. Switching off the
character-class rules is not reported: NIST SP 800-63B advises against them.

### SL042

**Failed sign-ins are not limited.** `PasswordSignInAsync(…, lockoutOnFailure: false)` (the value in many templates),
`CheckPasswordSignInAsync(…, false)`, `Lockout.AllowedForNewUsers = false`.
