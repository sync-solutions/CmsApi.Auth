using System.Security.Cryptography;

namespace CmsApi.Auth.Helpers;

public class PasswordHasher
{
    public static string HashPassword(string password)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);

        var hash = new Rfc2898DeriveBytes(password, salt, 10000, HashAlgorithmName.SHA256);

        byte[] hashBytes = hash.GetBytes(32);

        byte[] hashWithSalt = new byte[48];
        Buffer.BlockCopy(salt, 0, hashWithSalt, 0, 16);
        Buffer.BlockCopy(hashBytes, 0, hashWithSalt, 16, 32);

        return Convert.ToBase64String(hashWithSalt);
    }

    public static bool VerifyPassword(string password, string storedHash)
    {
        byte[] hashWithSalt = Convert.FromBase64String(storedHash);

        byte[] salt = new byte[16];
        Buffer.BlockCopy(hashWithSalt, 0, salt, 0, 16);

        var hash = new Rfc2898DeriveBytes(password, salt, 10000, HashAlgorithmName.SHA256);
        byte[] hashBytes = hash.GetBytes(32);

        for (int i = 0; i < 32; i++)
        {
            if (hashWithSalt[i + 16] != hashBytes[i])
                return false;
        }

        return true;
    }
}
