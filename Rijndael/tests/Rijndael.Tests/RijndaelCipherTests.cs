using Rijndael.Core.GaloisField;
using Rijndael.Core.Rijndael;
using Xunit;

namespace Rijndael.Tests;

public class RijndaelCipherTests
{
    private static RijndaelCipher Aes128()
    {
        var c = new RijndaelCipher(new Gf256(0x11B), 128);
        return c;
    }

    [Fact]
    public void Fips197_AppendixC1_Aes128()
    {
        // FIPS-197 C.1
        var cipher = Aes128();
        var key = Hex("000102030405060708090a0b0c0d0e0f");
        var pt = Hex("00112233445566778899aabbccddeeff");
        cipher.SetKey(key);
        var ct = cipher.Encrypt(pt);
        Assert.Equal(Hex("69c4e0d86a7b0430d8cdb78070b4c55a"), ct);

        var back = cipher.Decrypt(ct);
        Assert.Equal(pt, back);
    }

    [Fact]
    public void Fips197_AppendixC2_Aes192()
    {
        var cipher = new RijndaelCipher(new Gf256(0x11B), 128);
        var key = Hex("000102030405060708090a0b0c0d0e0f1011121314151617");
        var pt = Hex("00112233445566778899aabbccddeeff");
        cipher.SetKey(key);
        var ct = cipher.Encrypt(pt);
        Assert.Equal(Hex("dda97ca4864cdfe06eaf70a0ec0d7191"), ct);
        Assert.Equal(pt, cipher.Decrypt(ct));
    }

    [Fact]
    public void Fips197_AppendixC3_Aes256()
    {
        var cipher = new RijndaelCipher(new Gf256(0x11B), 128);
        var key = Hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        var pt = Hex("00112233445566778899aabbccddeeff");
        cipher.SetKey(key);
        var ct = cipher.Encrypt(pt);
        Assert.Equal(Hex("8ea2b7ca516745bfeafc49904b496089"), ct);
        Assert.Equal(pt, cipher.Decrypt(ct));
    }

    [Fact]
    public void BlockSize192_Roundtrip()
    {
        var cipher = new RijndaelCipher(new Gf256(0x11B), 192);
        cipher.SetKey(Hex("000102030405060708090a0b0c0d0e0f"));
        var pt = new byte[24];
        for (int i = 0; i < pt.Length; i++) pt[i] = (byte)i;
        var ct = cipher.Encrypt(pt);
        Assert.Equal(24, ct.Length);
        Assert.NotEqual(pt, ct);
        Assert.Equal(pt, cipher.Decrypt(ct));
    }

    [Fact]
    public void BlockSize256_Roundtrip()
    {
        var cipher = new RijndaelCipher(new Gf256(0x11B), 256);
        cipher.SetKey(Hex("000102030405060708090a0b0c0d0e0f"));
        var pt = new byte[32];
        for (int i = 0; i < pt.Length; i++) pt[i] = (byte)i;
        var ct = cipher.Encrypt(pt);
        Assert.Equal(32, ct.Length);
        Assert.Equal(pt, cipher.Decrypt(ct));
    }

    [Theory]
    [InlineData(128)]
    [InlineData(192)]
    [InlineData(256)]
    public void Roundtrip_RandomData_AllKeySizes(int keyBits)
    {
        var cipher = Aes128();
        var key = new byte[keyBits / 8];
        new Random(42).NextBytes(key);
        cipher.SetKey(key);

        var pt = new byte[16];
        new Random(43).NextBytes(pt);
        Assert.Equal(pt, cipher.Decrypt(cipher.Encrypt(pt)));
    }

    [Fact]
    public void Encrypt_ThrowsOnWrongBlockSize()
    {
        var cipher = Aes128();
        cipher.SetKey(new byte[16]);
        Assert.Throws<ArgumentException>(() => cipher.Encrypt(new byte[15]));
    }

    [Fact]
    public void Decrypt_ThrowsOnWrongBlockSize()
    {
        var cipher = Aes128();
        cipher.SetKey(new byte[16]);
        Assert.Throws<ArgumentException>(() => cipher.Decrypt(new byte[17]));
    }

    [Fact]
    public void SetKey_ThrowsOnInvalidLength()
    {
        var cipher = Aes128();
        Assert.Throws<ArgumentException>(() => cipher.SetKey(new byte[15]));
    }

    [Fact]
    public void Constructor_ThrowsOnInvalidBlockSize()
    {
        Assert.Throws<ArgumentException>(() => new RijndaelCipher(new Gf256(0x11B), 100));
    }

    [Fact]
    public void Encrypt_DoesNotMutateInput()
    {
        var cipher = Aes128();
        cipher.SetKey(new byte[16]);
        var pt = new byte[16];
        pt[0] = 1; pt[15] = 2;
        var copy = (byte[])pt.Clone();
        cipher.Encrypt(pt);
        Assert.Equal(copy, pt);
    }

    [Fact]
    public void DifferentKeys_ProduceDifferentCiphertext()
    {
        var cipher = Aes128();
        var pt = new byte[16];
        cipher.SetKey(Enumerable.Repeat((byte)0, 16).ToArray());
        var ct1 = cipher.Encrypt(pt);
        cipher.SetKey(Enumerable.Repeat((byte)1, 16).ToArray());
        var ct2 = cipher.Encrypt(pt);
        Assert.NotEqual(ct1, ct2);
    }

    private static byte[] Hex(string s) =>
        Convert.FromHexString(s);
}