using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace VulnerableShop.Vulnerable;

[ApiController, Route("vulnerable/files")]
public class FilesController(IHttpClientFactory http) : ControllerBase
{
    private const string InvoiceFolder = "/var/shop/invoices";

    // ?name=../../../etc/passwd
    [HttpGet("invoice")]
    public IActionResult Invoice(string name) =>
        File(System.IO.File.ReadAllBytes(Path.Combine(InvoiceFolder, name)), "application/pdf");

    [HttpPost("upload")]
    public async Task<IActionResult> Upload(IFormFile file)
    {
        await using var target = new FileStream(Path.Combine("uploads", file.FileName), FileMode.Create);
        await file.CopyToAsync(target);
        return Ok();
    }

    // ?host=example.org;cat /etc/passwd
    [HttpGet("ping")]
    public IActionResult Ping(string host)
    {
        using var process = Process.Start("/bin/sh", "-c \"ping -c 1 " + host + "\"");
        return Ok(process.Id);
    }

    // ?url=http://169.254.169.254/latest/meta-data/
    [HttpGet("preview")]
    public async Task<IActionResult> Preview(string url) => Ok(await http.CreateClient().GetStringAsync(url));

    [HttpGet("continue")]
    public IActionResult Continue(string returnUrl) => Redirect(returnUrl);

    [HttpGet("hello")]
    public IActionResult Hello(string name) => Content("<h1>Hello " + name + "</h1>", "text/html");
}
