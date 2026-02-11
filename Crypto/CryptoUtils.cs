using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Formats.Asn1;

namespace OAuthBandit.Crypto;

public static class CryptoUtils
{
    // dpapi p/invoke stuff
    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool CryptUnprotectData(
        ref DATA_BLOB pDataIn, IntPtr ppszDataDescr, IntPtr pOptionalEntropy,
        IntPtr pvReserved, IntPtr pPromptStruct, uint dwFlags, ref DATA_BLOB pDataOut);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr hMem);

    [StructLayout(LayoutKind.Sequential)]
    private struct DATA_BLOB
    {
        public int cbData;
        public IntPtr pbData;
    }

    public static byte[]? DpapiDecrypt(byte[] encrypted)
    {
        var dataIn = new DATA_BLOB();
        var dataOut = new DATA_BLOB();
        try
        {
            dataIn.cbData = encrypted.Length;
            dataIn.pbData = Marshal.AllocHGlobal(encrypted.Length);
            Marshal.Copy(encrypted, 0, dataIn.pbData, encrypted.Length);

            if (!CryptUnprotectData(ref dataIn, IntPtr.Zero, IntPtr.Zero,
                    IntPtr.Zero, IntPtr.Zero, 0, ref dataOut))
                return null;

            var result = new byte[dataOut.cbData];
            Marshal.Copy(dataOut.pbData, result, 0, dataOut.cbData);
            return result;
        }
        catch { return null; }
        finally
        {
            if (dataIn.pbData != IntPtr.Zero) Marshal.FreeHGlobal(dataIn.pbData);
            if (dataOut.pbData != IntPtr.Zero) LocalFree(dataOut.pbData);
        }
    }

    public static byte[]? AesGcmDecrypt(byte[] key, byte[] iv, byte[] ciphertext, byte[] tag)
    {
        try
        {
            using var aes = new AesGcm(key, tag.Length);
            var plaintext = new byte[ciphertext.Length];
            aes.Decrypt(iv, ciphertext, tag, plaintext);
            return plaintext;
        }
        catch { return null; }
    }

    // aes key unwrap - rfc 3394 implementation
    public static byte[]? AesKeyUnwrap(byte[] kek, byte[] wrappedKey)
    {
        try
        {
            if (wrappedKey.Length < 24 || wrappedKey.Length % 8 != 0) return null;
            int n = (wrappedKey.Length / 8) - 1;
            byte[] a = new byte[8];
            byte[][] r = new byte[n][];

            Array.Copy(wrappedKey, 0, a, 0, 8);
            for (int i = 0; i < n; i++)
            {
                r[i] = new byte[8];
                Array.Copy(wrappedKey, (i + 1) * 8, r[i], 0, 8);
            }

            using var aesEcb = Aes.Create();
            aesEcb.Key = kek;
            aesEcb.Mode = CipherMode.ECB;
            aesEcb.Padding = PaddingMode.None;
            using var decryptor = aesEcb.CreateDecryptor();

            byte[] block = new byte[16];
            for (int j = 5; j >= 0; j--)
            {
                for (int i = n; i >= 1; i--)
                {
                    long t = (long)n * j + i;
                    byte[] tBytes = BitConverter.GetBytes(t);
                    if (BitConverter.IsLittleEndian) Array.Reverse(tBytes);

                    byte[] xorA = new byte[8];
                    for (int k = 0; k < 8; k++) xorA[k] = (byte)(a[k] ^ tBytes[k]);

                    Array.Copy(xorA, 0, block, 0, 8);
                    Array.Copy(r[i - 1], 0, block, 8, 8);

                    byte[] dec = decryptor.TransformFinalBlock(block, 0, 16);
                    Array.Copy(dec, 0, a, 0, 8);
                    Array.Copy(dec, 8, r[i - 1], 0, 8);
                }
            }

            // verify the default IV bytes
            byte[] expectedIV = { 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6 };
            if (!a.SequenceEqual(expectedIV)) return null;

            byte[] result = new byte[n * 8];
            for (int i = 0; i < n; i++) Array.Copy(r[i], 0, result, i * 8, 8);
            return result;
        }
        catch { return null; }
    }

    public static string DecodeBase64(string encoded)
    {
        try { return System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(encoded)); }
        catch { return ""; }
    }

    public static byte[] DecodeBase64Url(string input)
    {
        try
        {
            string s = input.Replace('-', '+').Replace('_', '/');
            int pad = (4 - s.Length % 4) % 4;
            s += new string('=', pad);
            return Convert.FromBase64String(s);
        }
        catch { return Array.Empty<byte>(); }
    }

    // parse CMS enveloped data structure from WAM blobs
    // this took forever to get right tbh
    public static CmsData? ParseCmsEnvelopedData(byte[] buffer)
    {
        try
        {
            var reader = new AsnReader(buffer, AsnEncodingRules.DER);
            // ContentInfo SEQUENCE
            var contentInfo = reader.ReadSequence();
            // contentType OID
            string oid = contentInfo.ReadObjectIdentifier();
            if (oid != "1.2.840.113549.1.7.3") return null; // enveloped-data

            // content [0] EXPLICIT
            var contentTag = new Asn1Tag(TagClass.ContextSpecific, 0, true);
            var content0 = contentInfo.ReadSequence(contentTag);

            // EnvelopedData SEQUENCE
            var envelopedData = content0.ReadSequence();
            // version
            envelopedData.ReadInteger();

            // recipientInfos SET
            var recipientInfos = envelopedData.ReadSetOf();

            byte[]? kek = null;
            byte[]? encryptedCek = null;

            while (recipientInfos.HasData)
            {
                var tag = recipientInfos.PeekTag();
                // KEKRecipientInfo is [2]
                if (tag.TagClass == TagClass.ContextSpecific && tag.TagValue == 2)
                {
                    var kekri = recipientInfos.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 2, true));
                    // version
                    kekri.ReadInteger();
                    // KEKIdentifier SEQUENCE
                    var kekId = kekri.ReadSequence();
                    kek = kekId.ReadOctetString();
                    // skip remaining kekId fields
                    while (kekId.HasData) kekId.ReadEncodedValue();

                    // keyEncryptionAlgorithm - skip
                    kekri.ReadSequence();
                    // encryptedKey
                    encryptedCek = kekri.ReadOctetString();
                    break;
                }
                else
                {
                    recipientInfos.ReadEncodedValue(); // skip
                }
            }

            if (kek == null || encryptedCek == null) return null;

            // EncryptedContentInfo SEQUENCE
            var encContentInfo = envelopedData.ReadSequence();
            // contentType OID - skip
            encContentInfo.ReadObjectIdentifier();
            // contentEncryptionAlgorithm SEQUENCE
            var algo = encContentInfo.ReadSequence();
            algo.ReadObjectIdentifier(); // algorithm OID
            // GCMParameters SEQUENCE
            var gcmParams = algo.ReadSequence();
            byte[] iv = gcmParams.ReadOctetString();

            // encryptedContent [0] IMPLICIT OCTET STRING
            var encTag = new Asn1Tag(TagClass.ContextSpecific, 0);
            byte[] encryptedContent = encContentInfo.ReadOctetString(encTag);

            return new CmsData
            {
                Kek = kek,
                EncryptedCek = encryptedCek,
                Iv = iv,
                EncryptedContent = encryptedContent
            };
        }
        catch { return null; }
    }
}

public class CmsData
{
    public byte[] Kek { get; set; } = Array.Empty<byte>();
    public byte[] EncryptedCek { get; set; } = Array.Empty<byte>();
    public byte[] Iv { get; set; } = Array.Empty<byte>();
    public byte[] EncryptedContent { get; set; } = Array.Empty<byte>();
}
