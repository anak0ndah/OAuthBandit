using System.Security.Cryptography;
using System.Text;

namespace OAuthBandit.Utils;

public static class EncodingUtils
{
    public static string GetPublisherId(string publisher)
    {
        var hash = SHA256.HashData(Encoding.Unicode.GetBytes(publisher));
        return Base32EncodePublisher(hash[..8]);
    }

    private static string Base32EncodePublisher(byte[] data)
    {
        const string digits = "0123456789abcdefghjkmnpqrstvwxyz";
        var sb = new StringBuilder();

        for (int i = 0; i < data.Length; i += 5)
        {
            byte b0 = data[i];
            byte b1 = i + 1 < data.Length ? data[i + 1] : (byte)0;
            byte b2 = i + 2 < data.Length ? data[i + 2] : (byte)0;
            byte b3 = i + 3 < data.Length ? data[i + 3] : (byte)0;
            byte b4 = i + 4 < data.Length ? data[i + 4] : (byte)0;

            sb.Append(digits[(b0 & 0xF8) >> 3]);
            sb.Append(digits[((b0 & 0x07) << 2) | ((b1 & 0xC0) >> 6)]);
            sb.Append(digits[(b1 & 0x3E) >> 1]);
            sb.Append(digits[((b1 & 0x01) << 4) | ((b2 & 0xF0) >> 4)]);
            sb.Append(digits[((b2 & 0x0F) << 1) | ((b3 & 0x80) >> 7)]);
            sb.Append(digits[(b3 & 0x7C) >> 2]);
            sb.Append(digits[((b3 & 0x03) << 3) | ((b4 & 0xE0) >> 5)]);
            sb.Append(digits[b4 & 0x1F]);
        }

        // publisher IDs are always 13 chars
        return sb.Length > 13 ? sb.ToString()[..13] : sb.ToString();
    }

    public static string? FormatGuidFromBytes(byte[] data, int offset)
    {
        if (data.Length < offset + 16) return null;
        return $"{data[offset + 3]:x2}{data[offset + 2]:x2}{data[offset + 1]:x2}{data[offset + 0]:x2}-" +
               $"{data[offset + 5]:x2}{data[offset + 4]:x2}-" +
               $"{data[offset + 7]:x2}{data[offset + 6]:x2}-" +
               $"{data[offset + 8]:x2}{data[offset + 9]:x2}-" +
               $"{data[offset + 10]:x2}{data[offset + 11]:x2}{data[offset + 12]:x2}" +
               $"{data[offset + 13]:x2}{data[offset + 14]:x2}{data[offset + 15]:x2}";
    }
}
