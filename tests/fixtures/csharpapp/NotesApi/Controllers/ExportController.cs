using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;

namespace NotesApi.Controllers;

[ApiController]
[Route("api/[controller]")]
public class ExportController : ControllerBase
{
    [HttpPost("{name}")]
    public IActionResult Export(string name)
    {
        var p = Process.Start("zip", "-r " + name + ".zip notes");
        p?.WaitForExit();
        return Ok(new { file = name + ".zip", sum = Checksum(name) });
    }

    private static string Checksum(string name)
    {
        var bytes = MD5.HashData(Encoding.UTF8.GetBytes(name));
        return Convert.ToHexString(bytes);
    }
}
