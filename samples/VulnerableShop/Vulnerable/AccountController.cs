using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;

namespace VulnerableShop.Vulnerable;

[ApiController, Route("vulnerable/account")]
public class AccountController(ShopDb db, ILogger<AccountController> logger) : ControllerBase
{
    private const string WebhookSecret = "whsec-4f9a1c77e2b04d58";
    private static readonly Random Random = new();

    public record LoginRequest(string Email, string Password);

    [HttpPost("login")]
    public IActionResult Login(LoginRequest request)
    {
        logger.LogInformation("Login attempt for {Email} with {Password}", request.Email, request.Password);
        var hash = Convert.ToHexString(MD5.HashData(Encoding.UTF8.GetBytes(request.Password)));
        var customer = db.Customers.FirstOrDefault(c => c.Email == request.Email);
        if (customer is null || customer.PasswordHash != hash) return Unauthorized();

        Response.Cookies.Append("session", NewSessionToken(), new CookieOptions());
        return Ok();
    }

    // The client can send "isAdmin": true and "credit": 100000
    [HttpPut("profile")]
    public IActionResult UpdateProfile(Customer customer)
    {
        db.Update(customer);
        db.SaveChanges();
        return Ok();
    }

    [HttpPost("webhook")]
    public IActionResult Webhook([FromHeader(Name = "X-Signature")] string signature, [FromBody] string body)
    {
        var expectedSignature = Convert.ToHexString(HMACSHA256.HashData(Encoding.UTF8.GetBytes(WebhookSecret), Encoding.UTF8.GetBytes(body)));
        if (expectedSignature != signature) return Unauthorized();
        try
        {
            return Ok(body.Length);
        }
        catch (Exception ex)
        {
            return StatusCode(500, ex.ToString());
        }
    }

    private static string NewSessionToken()
    {
        var bytes = new byte[16];
        Random.NextBytes(bytes);
        return Convert.ToHexString(bytes);
    }
}
