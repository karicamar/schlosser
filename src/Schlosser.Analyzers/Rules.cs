using Microsoft.CodeAnalysis;

namespace Schlosser;

/// <summary>All rules in one place. The ids are stable: they are used in #pragma, .editorconfig and SARIF.</summary>
public static class Rules
{
    public const string Category = "Security";
    private const string Docs = "https://github.com/karicamar/schlosser/blob/main/docs/rules.md#";

    // ---- Injection: request data followed to a dangerous call (taint analysis) ----

    public static readonly DiagnosticDescriptor SqlInjection = Rule("SL001", "SQL injection",
        "SQL injection: {0} flows into {1}{2}. Pass the value as a parameter instead of building the SQL text.",
        DiagnosticSeverity.Warning, "CWE-89",
        "Request data that becomes part of the SQL text lets an attacker change the query. Use parameters (@name), FromSqlInterpolated or LINQ.",
        compilationEnd: true);

    public static readonly DiagnosticDescriptor SqlBuiltFromStrings = Rule("SL002", "SQL text is built from strings",
        "The SQL text for {0} is built from non-constant strings ({1}). Use parameters, or make sure the value can never come from a user.",
        DiagnosticSeverity.Info, "CWE-89",
        "No path from request data was found, but the SQL text is assembled from variable strings. Numbers, dates, GUIDs and enums are not reported because they cannot carry SQL.",
        compilationEnd: true);

    public static readonly DiagnosticDescriptor CommandInjection = Rule("SL003", "Command injection",
        "Command injection: {0} flows into {1}{2}. Do not pass request data to a process; use a fixed program with an allow-list of arguments.",
        DiagnosticSeverity.Warning, "CWE-78",
        "Request data in a program name or argument string lets an attacker run their own commands on the server.",
        compilationEnd: true);

    public static readonly DiagnosticDescriptor PathTraversal = Rule("SL004", "Path traversal",
        "Path traversal: {0} flows into {1}{2}. Use Path.GetFileName on the value, or check that Path.GetFullPath stays below the base folder.",
        DiagnosticSeverity.Warning, "CWE-22",
        "A file name from the request can contain ../ or an absolute path and reach files outside the intended folder.",
        compilationEnd: true);

    public static readonly DiagnosticDescriptor OpenRedirect = Rule("SL005", "Open redirect",
        "Open redirect: {0} flows into {1}{2}. Use LocalRedirect or check Url.IsLocalUrl first.",
        DiagnosticSeverity.Warning, "CWE-601",
        "A redirect target from the request lets an attacker send users from your trusted address to a phishing site.",
        compilationEnd: true);

    public static readonly DiagnosticDescriptor Ssrf = Rule("SL006", "Server-side request forgery",
        "Server-side request forgery: {0} decides the address of {1}{2}. Compare the host against an allow-list before the request.",
        DiagnosticSeverity.Warning, "CWE-918",
        "If the request decides which host the server calls, an attacker can reach internal services and cloud metadata endpoints.",
        compilationEnd: true);

    public static readonly DiagnosticDescriptor Xss = Rule("SL007", "Cross-site scripting",
        "Cross-site scripting: {0} flows into {1}{2} without HTML encoding.",
        DiagnosticSeverity.Warning, "CWE-79",
        "Request data written as raw HTML runs as script in the browser of whoever opens the page.",
        compilationEnd: true);

    public static readonly DiagnosticDescriptor LdapInjection = Rule("SL008", "LDAP injection",
        "LDAP injection: {0} flows into {1}{2}. Escape the value for LDAP filters (RFC 4515) first.",
        DiagnosticSeverity.Warning, "CWE-90",
        "Request data in an LDAP filter lets an attacker change the directory query, for example to match every user.",
        compilationEnd: true);

    public static readonly DiagnosticDescriptor XPathInjection = Rule("SL009", "XPath injection",
        "XPath injection: {0} flows into {1}{2}. Use XPath variables or LINQ to XML instead of building the expression.",
        DiagnosticSeverity.Warning, "CWE-643",
        "Request data in an XPath expression lets an attacker change which nodes are selected.",
        compilationEnd: true);

    public static readonly DiagnosticDescriptor RegexInjection = Rule("SL010", "Regular expression from request data",
        "Regular expression denial of service: {0} is used as the pattern of {1}{2} without a timeout. Use Regex.Escape, a match timeout or RegexOptions.NonBacktracking.",
        DiagnosticSeverity.Warning, "CWE-1333",
        "A pattern chosen by the attacker can take exponential time and block a thread for minutes.",
        compilationEnd: true);

    public static readonly DiagnosticDescriptor MassAssignment = Rule("SL011", "Database entity bound from the request",
        "Mass assignment: '{0}' binds the request directly to the database entity '{1}'. The client can set every property, including {2}. Bind a request model with only the allowed fields.",
        DiagnosticSeverity.Warning, "CWE-915",
        "Model binding fills every public property the client sends. With an entity as the parameter that includes fields like IsAdmin, Role or Balance.",
        compilationEnd: true);

    public static readonly DiagnosticDescriptor RawHtmlInView = Rule("SL012", "Unencoded output in a Razor view",
        "Html.Raw writes {0} into the page without HTML encoding. If the value can contain text from a user, this is stored cross-site scripting; use @value, or sanitize the HTML with an allow-list.",
        DiagnosticSeverity.Warning, "CWE-79",
        "Razor encodes everything written with @value. Html.Raw switches that off, so the value must be HTML that the application built or sanitized itself.");

    // ---- Cryptography ----

    public static readonly DiagnosticDescriptor WeakHash = Rule("SL020", "Broken hash algorithm",
        "{0} is broken (collisions are practical). Use SHA-256 or better.",
        DiagnosticSeverity.Warning, "CWE-328",
        "MD5 and SHA-1 must not be used for signatures, integrity checks or passwords.");

    public static readonly DiagnosticDescriptor WeakCipher = Rule("SL021", "Weak cipher or cipher mode",
        "{0}. Use AES-GCM (AesGcm), or AES-CBC with a random IV plus an HMAC.",
        DiagnosticSeverity.Warning, "CWE-327",
        "DES, 3DES and RC2 are obsolete; ECB mode leaks patterns of the plaintext.");

    public static readonly DiagnosticDescriptor InsecureRandom = Rule("SL022", "Predictable random numbers for a secret",
        "System.Random is predictable and is used here for {0}. Use RandomNumberGenerator.",
        DiagnosticSeverity.Warning, "CWE-338",
        "System.Random is not a cryptographic generator: with a few outputs the next values can be computed. Tokens, passwords, codes and keys need RandomNumberGenerator.");

    public static readonly DiagnosticDescriptor HardCodedKey = Rule("SL023", "Hard-coded cryptographic key, IV or salt",
        "The {0} is hard-coded. Everyone with the source or the binary has it; load keys from configuration or a vault and generate IVs and salts randomly.",
        DiagnosticSeverity.Warning, "CWE-321",
        "A key in the source code cannot be rotated and is shared by every installation. A fixed IV or salt removes the protection they exist for.");

    public static readonly DiagnosticDescriptor WeakPasswordHash = Rule("SL024", "Weak password hashing",
        "{0}. Use PBKDF2 with SHA-256 and at least 100,000 iterations (OWASP: 600,000), or Argon2id/bcrypt.",
        DiagnosticSeverity.Warning, "CWE-916",
        "A fast hash or a low iteration count lets an attacker test billions of passwords per second after a database leak.");

    public static readonly DiagnosticDescriptor TimingComparison = Rule("SL025", "Secret compared in non-constant time",
        "'{0}' is compared with {1}, which stops at the first different character. Use CryptographicOperations.FixedTimeEquals.",
        DiagnosticSeverity.Warning, "CWE-208",
        "The response time of a normal comparison tells an attacker how many leading characters of a MAC, signature or token were right.");

    // ---- Secrets and configuration ----

    public static readonly DiagnosticDescriptor HardCodedSecret = Rule("SL030", "Hard-coded secret",
        "Hard-coded secret: {0}. Move it to user secrets, environment variables or a vault, and rotate it if it was ever committed.",
        DiagnosticSeverity.Warning, "CWE-798",
        "Secrets in source code end up in the repository history, in build artefacts and on every developer machine.");

    public static readonly DiagnosticDescriptor CertificateValidationDisabled = Rule("SL031", "TLS certificate validation is disabled",
        "{0} accepts every certificate, so anyone on the network path can read and change the traffic.",
        DiagnosticSeverity.Warning, "CWE-295",
        "A validation callback that always returns true removes the protection of TLS. For internal CAs, add the CA to the trust store or pin the certificate.");

    public static readonly DiagnosticDescriptor OldTlsVersion = Rule("SL032", "Outdated TLS version",
        "{0} is an outdated protocol version. Leave the choice to the operating system (SslProtocols.None) or use TLS 1.2 and 1.3.",
        DiagnosticSeverity.Warning, "CWE-327",
        "SSL 3.0, TLS 1.0 and TLS 1.1 have known attacks and are disabled by browsers and by BSI TR-02102-2.");

    public static readonly DiagnosticDescriptor InsecureDeserialization = Rule("SL033", "Insecure deserialization",
        "{0}. Data from outside can then create arbitrary types, which leads to remote code execution.",
        DiagnosticSeverity.Warning, "CWE-502",
        "BinaryFormatter and similar serializers, and JSON with type names enabled, let the sender choose which .NET types are created.");

    public static readonly DiagnosticDescriptor Xxe = Rule("SL034", "XML external entities are enabled",
        "{0} lets an XML document read local files or call internal addresses (XXE). Use DtdProcessing.Prohibit and no XmlResolver.",
        DiagnosticSeverity.Warning, "CWE-611",
        "With DTD processing and a resolver, an attacker's XML can include file:///etc/passwd or internal URLs in the parsed result.");

    public static readonly DiagnosticDescriptor JwtValidationDisabled = Rule("SL035", "Token validation is switched off",
        "{0} = {1} switches off a check of the token: {2}.",
        DiagnosticSeverity.Warning, "CWE-347",
        "Each TokenValidationParameters switch protects against a concrete attack: forged tokens, expired tokens, tokens issued for another API.");

    public static readonly DiagnosticDescriptor CookieFlags = Rule("SL036", "Cookie without protective flags",
        "{0}",
        DiagnosticSeverity.Warning, "CWE-614",
        "Without Secure the cookie is sent over plain HTTP; without HttpOnly any script on the page can read it.");

    public static readonly DiagnosticDescriptor CorsAnyOrigin = Rule("SL037", "CORS allows every origin with credentials",
        "{0}. Any website can then call the API with the visitor's cookies and read the answers. List the allowed origins with WithOrigins.",
        DiagnosticSeverity.Warning, "CWE-942",
        "Reflecting every origin together with credentials removes the same-origin protection of the browser.");

    public static readonly DiagnosticDescriptor AntiForgeryDisabled = Rule("SL038", "Anti-forgery protection is switched off",
        "{0} switches off the CSRF token check. With cookie authentication, another website can then submit this request for a signed-in user.",
        DiagnosticSeverity.Warning, "CWE-352",
        "Only switch the check off for endpoints that do not use cookie authentication, for example webhooks with their own signature.");

    public static readonly DiagnosticDescriptor SecretInLog = Rule("SL039", "Secret written to the log",
        "'{0}' is written to the log. Logs are read by many people and shipped to other systems; log that the value was present, not the value.",
        DiagnosticSeverity.Warning, "CWE-532",
        "Passwords, tokens and keys in log files are a common finding in audits and a common way credentials leak.");

    public static readonly DiagnosticDescriptor ExceptionDetails = Rule("SL040", "Exception details sent to the client",
        "{0} sends internal details (stack trace, SQL, file paths) to the client. Log the exception and return a generic error.",
        DiagnosticSeverity.Warning, "CWE-209",
        "Stack traces and exception texts tell an attacker the framework, the database and the file layout.");

    public static readonly DiagnosticDescriptor WeakPasswordPolicy = Rule("SL041", "Password policy allows very short passwords",
        "RequiredLength = {0} accepts passwords of {0} characters. NIST SP 800-63B and BSI ORP.4 ask for at least 8; length matters more than character classes.",
        DiagnosticSeverity.Warning, "CWE-521",
        "Short passwords are guessed online within the lockout limits and cracked offline within seconds.");

    public static readonly DiagnosticDescriptor NoLockout = Rule("SL042", "Failed sign-ins are not limited",
        "{0}, so passwords can be guessed without limit. Count failed attempts and lock the account for a while.",
        DiagnosticSeverity.Warning, "CWE-307",
        "Without a lockout or rate limit, password spraying and brute force only need time.");

    public static readonly DiagnosticDescriptor[] All =
    {
        SqlInjection, SqlBuiltFromStrings, CommandInjection, PathTraversal, OpenRedirect, Ssrf, Xss, LdapInjection, XPathInjection,
        RegexInjection, MassAssignment, RawHtmlInView, WeakHash, WeakCipher, InsecureRandom, HardCodedKey, WeakPasswordHash, TimingComparison,
        HardCodedSecret, CertificateValidationDisabled, OldTlsVersion, InsecureDeserialization, Xxe, JwtValidationDisabled,
        CookieFlags, CorsAnyOrigin, AntiForgeryDisabled, SecretInLog, ExceptionDetails, WeakPasswordPolicy, NoLockout,
    };

    /// <summary>The CWE of a rule, e.g. "CWE-89". Stored as a custom tag so it also ends up in SARIF.</summary>
    public static string Cwe(DiagnosticDescriptor rule)
    {
        foreach (var tag in rule.CustomTags)
            if (tag.StartsWith("CWE-", System.StringComparison.Ordinal)) return tag;
        return "";
    }

    private static DiagnosticDescriptor Rule(string id, string title, string message, DiagnosticSeverity severity, string cwe,
        string description, bool compilationEnd = false)
    {
        var tags = compilationEnd
            ? new[] { cwe, WellKnownDiagnosticTags.CompilationEnd }
            : new[] { cwe };
        return new DiagnosticDescriptor(id, title, message, Category, severity, isEnabledByDefault: true,
            description: description, helpLinkUri: Docs + id.ToLowerInvariant(), customTags: tags);
    }
}
