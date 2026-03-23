using System.Security.Cryptography;
using System.Text;

namespace GuardianConfigManager.Services;

public static class HashService
{
    public static string ComputeSha256(string input)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
    }
}
