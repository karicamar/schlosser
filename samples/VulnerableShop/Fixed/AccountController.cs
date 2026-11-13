using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;

namespace VulnerableShop.Fixed;

[ApiController, Route("fixed/account")]
public class AccountController(ShopDb db, IConfiguration configuration, ILogger<AccountController> logger) : ControllerBase
{
    public record LoginRequest(string Email, string Password);
    public record ProfileRequest(string DisplayName);

    [HttpPost("login")]
    public IActionResult Login(LoginRequest request)
    {
        logger.LogInformation("Login attempt for {Email}", request.Email);
        var customer = db.Customers.FirstOrDefault(c => c.Email == request.Email);
        if (customer is null || !Verify(request.Password, customer.PasswordHash)) return Unauthorized();

        Response.Cookies.Append("session", NewSessionToken(),
            new CookieOptions { Secure = true, HttpOnly = true, SameSite = SameSiteMode.Strict });
        return Ok();
    }

    // Only the fields a customer may change
    [HttpPut("profile/{id:int}")]
    public IActionResult UpdateProfile(int id, ProfileRequest request)
    {
        var customer = db.Customers.Find(id);
        if (customer is null) return NotFound();
        customer.DisplayName = request.DisplayName;
        db.SaveChanges();
        return Ok();
    }

    [HttpPost("webhook")]
    public IActionResult Webhook([FromHeader(Name = "X-Signature")] string signature, [FromBody] string body)
    {
        var key = Encoding.UTF8.GetBytes(configuration["Webhook:Secret"]!);
        var expected = HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(body));
        byte[] provided;
        try
        {
            provided = Convert.FromHexString(signature);
        }
        catch (FormatException)
        {
            return Unauthorized();
        }

        if (!CryptographicOperations.FixedTimeEquals(expected, provided)) return Unauthorized();
        return Ok(body.Length);
    }

    /// <summary>Stored as "salt:hash" in hex, PBKDF2-SHA256 with 600,000 iterations.</summary>
    private static bool Verify(string password, string stored)
    {
        var parts = stored.Split(':');
        if (parts.Length != 2) return false;
        var salt = Convert.FromHexString(parts[0]);
        var expected = Convert.FromHexString(parts[1]);
        var actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, 600_000, HashAlgorithmName.SHA256, expected.Length);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    private static string NewSessionToken() => Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
}
