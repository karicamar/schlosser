using System.Diagnostics;
using System.Net;
using Microsoft.AspNetCore.Mvc;

namespace VulnerableShop.Fixed;

[ApiController, Route("fixed/files")]
public class FilesController(IHttpClientFactory http) : ControllerBase
{
    private const string InvoiceFolder = "/var/shop/invoices";

    [HttpGet("invoice")]
    public IActionResult Invoice(string name) =>
        File(System.IO.File.ReadAllBytes(Path.Combine(InvoiceFolder, Path.GetFileName(name))), "application/pdf");

    [HttpPost("upload")]
    public async Task<IActionResult> Upload(IFormFile file)
    {
        // the server chooses the name; only the extension comes from the client
        var name = Guid.NewGuid() + Path.GetExtension(file.FileName);
        await using var target = new FileStream(Path.Combine("uploads", name), FileMode.Create);
        await file.CopyToAsync(target);
        return Ok();
    }

    [HttpGet("ping")]
    public IActionResult Ping(string host)
    {
        // no shell, and the value is checked to be an IP address before it becomes an argument
        if (!IPAddress.TryParse(host, out var address)) return BadRequest();
        var info = new ProcessStartInfo("ping");
        info.ArgumentList.Add("-c");
        info.ArgumentList.Add("1");
        info.ArgumentList.Add(address.ToString());
        using var process = Process.Start(info);
        return Ok(process?.Id);
    }

    // the host is fixed, the request only chooses the product
    [HttpGet("preview")]
    public async Task<IActionResult> Preview(int productId) =>
        Ok(await http.CreateClient().GetStringAsync("https://images.example.org/products/" + productId));

    [HttpGet("continue")]
    public IActionResult Continue(string returnUrl) => LocalRedirect(returnUrl);

    [HttpGet("hello")]
    public IActionResult Hello(string name) => Content("<h1>Hello " + WebUtility.HtmlEncode(name) + "</h1>", "text/html");
}
