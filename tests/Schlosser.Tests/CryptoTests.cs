namespace Schlosser.Tests;

public class CryptoTests
{
    [Fact]
    public Task Broken_hashes()
    {
        return Verify.Analyzer<CryptoAnalyzer>("""
            using System.Security.Cryptography;

            public class Hashes
            {
                public void Run(byte[] data, RSA rsa)
                {
                    var a = {|SL020:MD5.Create()|};
                    var b = {|SL020:MD5.HashData(data)|};
                    var c = {|SL020:SHA1.HashData(data)|};
                    var d = {|SL020:new HMACMD5(data)|};
                    var e = rsa.SignData(data, {|SL020:HashAlgorithmName.SHA1|}, RSASignaturePadding.Pkcs1);

                    var ok1 = SHA256.HashData(data);
                    var ok2 = SHA512.Create();
                    // HMAC-SHA1 is still sound and what TOTP (RFC 6238) requires
                    var ok3 = new HMACSHA1(data);
                    var ok4 = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
                }
            }
            """);
    }

    [Fact]
    public Task Weak_ciphers_and_ecb()
    {
        return Verify.Analyzer<CryptoAnalyzer>("""
            using System.Security.Cryptography;

            public class Ciphers
            {
                public void Run(byte[] data)
                {
                    using var des = {|SL021:DES.Create()|};
                    using var tripleDes = {|SL021:TripleDES.Create()|};
                    using var aes = Aes.Create();
                    aes.Mode = {|SL021:CipherMode.ECB|};
                    var block = {|SL021:aes.EncryptEcb(data, PaddingMode.PKCS7)|};

                    using var good = Aes.Create();
                    good.Mode = CipherMode.CBC;
                }
            }
            """);
    }

    [Fact]
    public Task Random_for_secrets_but_not_for_everything()
    {
        return Verify.Analyzer<CryptoAnalyzer>("""
            public class Generator
            {
                private readonly Random _random = new();

                public string CreateResetToken()
                {
                    var bytes = new byte[32];
                    {|SL022:_random.NextBytes(bytes)|};
                    return Convert.ToHexString(bytes);
                }

                public int Something()
                {
                    var otp = {|SL022:Random.Shared.Next(100000, 999999)|};
                    return otp;
                }

                public string NewPassword(int length)
                {
                    const string alphabet = "abcdefghijkmnpqrstuvwxyz23456789";
                    var chars = new char[length];
                    for (var i = 0; i < length; i++) chars[i] = alphabet[{|SL022:_random.Next(alphabet.Length)|}];
                    return new string(chars);
                }

                public string Charge()
                {
                    var code = {|SL022:new Random().Next(999999)|}.ToString("000000");
                    return code;
                }

                public string Tracking() => "1Z" + _random.Next(999).ToString("000");

                // Not secrets: jitter, sampling, shuffling a playlist
                public TimeSpan RetryDelay() => TimeSpan.FromMilliseconds(_random.Next(50, 250));
                public int PickServer(int count) => Random.Shared.Next(count);
                public double Sample() => _random.NextDouble();
            }
            """);
    }

    [Fact]
    public Task Hard_coded_keys_ivs_and_salts()
    {
        return Verify.Analyzer<CryptoAnalyzer>("""
            using System.Security.Cryptography;
            using System.Text;
            using Microsoft.Extensions.Configuration;
            using Microsoft.IdentityModel.Tokens;

            public class Keys
            {
                private static readonly byte[] StaticKey = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

                public void Run(byte[] data, IConfiguration configuration, string password)
                {
                    using var aes = Aes.Create();
                    aes.Key = {|SL023:Encoding.UTF8.GetBytes("0123456789abcdef")|};
                    aes.IV = {|SL023:new byte[16]|};
                    aes.Key = {|SL023:StaticKey|};

                    var literal = Convert.FromBase64String("c2VjcmV0LXNlY3JldC1zZWNyZXQ=");
                    using var hmac = new HMACSHA256({|SL023:literal|});

                    var signing = new SymmetricSecurityKey({|SL023:Encoding.UTF8.GetBytes("super-secret-signing-key-123456")|});
                    var derived = Rfc2898DeriveBytes.Pbkdf2(password, {|SL023:Encoding.ASCII.GetBytes("fixed-salt")|}, 600_000, HashAlgorithmName.SHA256, 32);

                    // from configuration or generated: fine
                    using var good = Aes.Create();
                    good.Key = Convert.FromBase64String(configuration["Crypto:Key"]!);
                    good.GenerateIV();
                    var goodSigning = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["Jwt:Key"]!));
                    var salt = RandomNumberGenerator.GetBytes(16);
                    var goodDerived = Rfc2898DeriveBytes.Pbkdf2(password, salt, 600_000, HashAlgorithmName.SHA256, 32);
                    using var goodHmac = new HMACSHA256(data);
                }
            }
            """);
    }

    [Fact]
    public Task Weak_password_hashing()
    {
        return Verify.Analyzer<CryptoAnalyzer>("""
            using System.Security.Cryptography;
            using System.Text;

            public class User { public string Password { get; set; } = ""; }

            public class Passwords
            {
                public void Run(string password, byte[] salt, User user, byte[] file)
                {
                    var a = {|SL024:SHA256.HashData(Encoding.UTF8.GetBytes(password))|};
                    using var sha = SHA512.Create();
                    var b = {|SL024:sha.ComputeHash(Encoding.UTF8.GetBytes(user.Password + "pepper"))|};

                    var c = Rfc2898DeriveBytes.Pbkdf2(password, salt, {|SL024:10_000|}, HashAlgorithmName.SHA256, 32);
                    var d = Rfc2898DeriveBytes.Pbkdf2(password, salt, 600_000, {|SL024:HashAlgorithmName.SHA1|}, 32);
            #pragma warning disable SYSLIB0041, SYSLIB0060
                    using var e = {|SL024:new Rfc2898DeriveBytes(password, salt)|};
                    using var f = {|SL024:new Rfc2898DeriveBytes(password, salt, 200_000)|};
            #pragma warning restore SYSLIB0041, SYSLIB0060

                    // one finding, not two: the password rule wins over "MD5 is broken"
                    var g = {|SL024:MD5.HashData(Encoding.UTF8.GetBytes(password))|};

                    var ok1 = Rfc2898DeriveBytes.Pbkdf2(password, salt, 600_000, HashAlgorithmName.SHA256, 32);
                    var ok2 = SHA256.HashData(file); // a checksum of a file is not password hashing
                    using var hmac = new HMACSHA256(salt);
                    var ok3 = hmac.ComputeHash(Encoding.UTF8.GetBytes(password)); // keyed
                }
            }
            """);
    }

    [Fact]
    public async Task Pbkdf2_message_names_the_iteration_count()
    {
        var diagnostics = await Verify.Diagnostics<CryptoAnalyzer>("""
            using System.Security.Cryptography;

            public class Passwords
            {
                public byte[] Hash(string password, byte[] salt) =>
                    Rfc2898DeriveBytes.Pbkdf2(password, salt, 10_000, HashAlgorithmName.SHA256, 32);
            }
            """);

        Assert.Equal(
            "PBKDF2 with only 10,000 iterations. Use PBKDF2 with SHA-256 and at least 100,000 iterations (OWASP: 600,000), or Argon2id/bcrypt.",
            Assert.Single(diagnostics).GetMessage());
    }

    [Fact]
    public Task Timing_unsafe_comparisons()
    {
        return Verify.Analyzer<CryptoAnalyzer>("""
            using System.Security.Cryptography;

            public class ApiClient { public string ApiKey { get; set; } = ""; public string Name { get; set; } = ""; }

            public class Webhook
            {
                public bool Check(byte[] body, byte[] key, string signatureHeader, ApiClient client, string providedKey, string tokenType)
                {
                    var computedSignature = Convert.ToHexString(HMACSHA256.HashData(key, body));
                    if ({|SL025:computedSignature == signatureHeader|}) return true;

                    var expectedMac = HMACSHA256.HashData(key, body);
                    var providedMac = Convert.FromHexString(signatureHeader);
                    if ({|SL025:expectedMac.SequenceEqual(providedMac)|}) return true;

                    if ({|SL025:client.ApiKey != providedKey|}) return false;
                    if ({|SL025:string.Equals(client.ApiKey, providedKey, StringComparison.Ordinal)|}) return true;

                    // constants, null checks and non-secrets are fine
                    if (tokenType == "Bearer") return false;
                    if (signatureHeader == null || computedSignature == string.Empty) return false;
                    if (client.Name == providedKey) return false;
                    // hashes of files and audit records are public: comparing them is an integrity check
                    var storedHash = Convert.ToHexString(SHA256.HashData(body));
                    if (storedHash != signatureHeader.Trim()) return false;
                    return CryptographicOperations.FixedTimeEquals(expectedMac, providedMac);
                }
            }
            """);
    }

    [Fact]
    public Task Comparison_inside_a_database_query_is_not_a_timing_issue()
    {
        return Verify.Analyzer<CryptoAnalyzer>("""
            using System.Linq.Expressions;

            public class Session { public string Token { get; set; } = ""; }

            public class Sessions
            {
                public Session? Find(IQueryable<Session> sessions, string token) =>
                    sessions.FirstOrDefault(s => s.Token == token);
            }
            """);
    }
}
