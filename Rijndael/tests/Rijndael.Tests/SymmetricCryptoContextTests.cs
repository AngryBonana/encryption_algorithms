using Rijndael.Core;
using Rijndael.Core.GaloisField;
using Rijndael.Core.Modes;
using Rijndael.Core.Padding;
using Rijndael.Core.Rijndael;
using Xunit;

namespace Rijndael.Tests;

public class SymmetricCryptoContextTests
{
    private static byte[] Key128 => Enumerable.Repeat((byte)0x2B, 16).ToArray();
    private static byte[] Iv => Enumerable.Range(0, 16).Select(i => (byte)i).ToArray();
    private static byte[] Delta => Enumerable.Range(0, 16).Select(i => (byte)(i + 1)).ToArray();

    private static SymmetricCryptoContext MakeCtx(
        CipherMode mode,
        PaddingMode padding = PaddingMode.PKCS7,
        byte[]? iv = null,
        byte[]? delta = null)
    {
        var cipher = new RijndaelCipher(new Gf256(0x11B), 128);
        var modeParams = delta is null ? Array.Empty<object>() : new object[] { delta };
        return new SymmetricCryptoContext(
            cipher, Key128, mode, padding,
            mode == CipherMode.ECB ? null : (iv ?? Iv),
            modeParams);
    }

    // ---------- Конструктор ----------

    [Fact]
    public void Ctor_NullCipher_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new SymmetricCryptoContext(null!, Key128, CipherMode.ECB, PaddingMode.PKCS7));
    }

    [Fact]
    public void Ctor_NullKey_Throws()
    {
        var cipher = new RijndaelCipher(new Gf256(0x11B), 128);
        Assert.Throws<ArgumentNullException>(() =>
            new SymmetricCryptoContext(cipher, null!, CipherMode.ECB, PaddingMode.PKCS7));
    }

    [Theory]
    [InlineData(CipherMode.CBC)]
    [InlineData(CipherMode.PCBC)]
    [InlineData(CipherMode.CFB)]
    [InlineData(CipherMode.OFB)]
    [InlineData(CipherMode.CTR)]
    [InlineData(CipherMode.RandomDelta)]
    public void Ctor_NonEcbWithoutIv_Throws(CipherMode mode)
    {
        var cipher = new RijndaelCipher(new Gf256(0x11B), 128);
        var p = mode == CipherMode.RandomDelta ? new object[] { Delta } : Array.Empty<object>();
        Assert.Throws<ArgumentException>(() =>
            new SymmetricCryptoContext(cipher, Key128, mode, PaddingMode.PKCS7, null, p));
    }

    [Fact]
    public void Ctor_WrongIvLength_Throws()
    {
        var cipher = new RijndaelCipher(new Gf256(0x11B), 128);
        Assert.Throws<ArgumentException>(() =>
            new SymmetricCryptoContext(cipher, Key128, CipherMode.CBC, PaddingMode.PKCS7, new byte[8]));
    }

    [Fact]
    public void Ctor_RandomDeltaWithoutDelta_Throws()
    {
        var cipher = new RijndaelCipher(new Gf256(0x11B), 128);
        Assert.Throws<ArgumentException>(() =>
            new SymmetricCryptoContext(cipher, Key128, CipherMode.RandomDelta, PaddingMode.PKCS7, Iv));
    }

    [Fact]
    public void Ctor_RandomDeltaWrongDeltaLength_Throws()
    {
        var cipher = new RijndaelCipher(new Gf256(0x11B), 128);
        Assert.Throws<ArgumentException>(() =>
            new SymmetricCryptoContext(cipher, Key128, CipherMode.RandomDelta, PaddingMode.PKCS7,
                Iv, new byte[8]));
    }

    // ---------- Roundtrip по режимам ----------

    public static IEnumerable<object[]> ModesAndData()
    {
        var sizes = new[] { 0, 1, 15, 16, 17, 32, 100, 1000 };
        var modes = new[]
        {
            CipherMode.ECB, CipherMode.CBC, CipherMode.PCBC,
            CipherMode.CFB, CipherMode.OFB, CipherMode.CTR, CipherMode.RandomDelta
        };
        foreach (var m in modes)
        foreach (var s in sizes)
            yield return new object[] { m, s };
    }

    [Theory]
    [MemberData(nameof(ModesAndData))]
    public void EncryptDecrypt_Roundtrip_AllModes(CipherMode mode, int size)
    {
        var ctx = MakeCtx(mode, PaddingMode.PKCS7, delta: mode == CipherMode.RandomDelta ? Delta : null);
        var data = new byte[size];
        new Random(size + 1).NextBytes(data);

        ctx.Encrypt(data, out var enc);
        Assert.Equal(0, enc.Length % 16);

        ctx.Decrypt(enc, out var dec);
        Assert.Equal(data, dec);
    }

    [Theory]
    [InlineData(CipherMode.ECB)]
    [InlineData(CipherMode.CBC)]
    [InlineData(CipherMode.PCBC)]
    [InlineData(CipherMode.CFB)]
    [InlineData(CipherMode.OFB)]
    [InlineData(CipherMode.CTR)]
    public void EncryptDecrypt_Roundtrip_ZerosPadding(CipherMode mode)
    {
        // Zeros при выровненных данных — специальный случай
        var ctx = MakeCtx(mode, PaddingMode.Zeros);
        var data = Enumerable.Range(1, 16).Select(i => (byte)i).ToArray();
        ctx.Encrypt(data, out var enc);
        ctx.Decrypt(enc, out var dec);
        Assert.Equal(data, dec);
    }

    // ---------- Детерминированность и свойства режимов ----------

    [Fact]
    public void Ecb_IsDeterministic()
    {
        var ctx = MakeCtx(CipherMode.ECB);
        var data = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        ctx.Encrypt(data, out var enc1);
        ctx.Encrypt(data, out var enc2);
        Assert.Equal(enc1, enc2);
    }

    [Fact]
    public void Ecb_RepeatedBlocksProduceRepeatedCiphertext()
    {
        var ctx = MakeCtx(CipherMode.ECB);
        var block = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray();
        var data = block.Concat(block).ToArray();
        ctx.Encrypt(data, out var enc);
        Assert.Equal(enc[..16], enc[16..32]);
    }

    [Fact]
    public void Cbc_DifferentIvsProduceDifferentCiphertext()
    {
        var data = new byte[32];
        var ctx1 = MakeCtx(CipherMode.CBC, iv: Enumerable.Repeat((byte)0, 16).ToArray());
        var ctx2 = MakeCtx(CipherMode.CBC, iv: Enumerable.Repeat((byte)1, 16).ToArray());
        ctx1.Encrypt(data, out var e1);
        ctx2.Encrypt(data, out var e2);
        Assert.NotEqual(e1, e2);
    }

    [Fact]
    public void Cbc_WrongIvDecrypt_ProducesGarbage()
    {
        var data = new byte[32];
        new Random(7).NextBytes(data);
        var ctx1 = MakeCtx(CipherMode.CBC, iv: Enumerable.Repeat((byte)0, 16).ToArray());
        var ctx2 = MakeCtx(CipherMode.CBC, iv: Enumerable.Repeat((byte)1, 16).ToArray());
        ctx1.Encrypt(data, out var enc);
        ctx2.Decrypt(enc, out var dec);
        Assert.NotEqual(data, dec);
    }

    [Fact]
    public void Ctr_EncryptEqualsDecrypt()
    {
        // CTR — симметричен
        var data = new byte[32];
        new Random(1).NextBytes(data);
        var ctx1 = MakeCtx(CipherMode.CTR);
        var ctx2 = MakeCtx(CipherMode.CTR);
        ctx1.Encrypt(data, out var enc);
        ctx2.Decrypt(enc, out var dec);
        Assert.Equal(data, dec);
    }

    [Fact]
    public void Ofb_EncryptEqualsDecrypt()
    {
        var data = new byte[32];
        new Random(2).NextBytes(data);
        var ctx1 = MakeCtx(CipherMode.OFB);
        var ctx2 = MakeCtx(CipherMode.OFB);
        ctx1.Encrypt(data, out var enc);
        ctx2.Decrypt(enc, out var dec);
        Assert.Equal(data, dec);
    }

    [Fact]
    public void RandomDelta_IsDeterministicForSameKeyIvDelta()
    {
        var data = new byte[32];
        new Random(3).NextBytes(data);
        var ctx1 = MakeCtx(CipherMode.RandomDelta, delta: Delta);
        var ctx2 = MakeCtx(CipherMode.RandomDelta, delta: Delta);
        ctx1.Encrypt(data, out var e1);
        ctx2.Encrypt(data, out var e2);
        Assert.Equal(e1, e2);
    }

    [Fact]
    public void RandomDelta_DifferentDeltaProduceDifferentCiphertext()
    {
        var data = new byte[32];
        var ctx1 = MakeCtx(CipherMode.RandomDelta, delta: Delta);
        var ctx2 = MakeCtx(CipherMode.RandomDelta,
            delta: Delta.Select(b => (byte)(b + 1)).ToArray());
        ctx1.Encrypt(data, out var e1);
        ctx2.Encrypt(data, out var e2);
        Assert.NotEqual(e1, e2);
    }

    // ---------- Ошибки при дешифровании ----------

    [Fact]
    public void Decrypt_NonBlockMultiple_Throws()
    {
        var ctx = MakeCtx(CipherMode.CBC);
        Assert.Throws<ArgumentException>(() => ctx.Decrypt(new byte[15], out _));
    }

    // ---------- Стриминговое API ----------

    [Theory]
    [InlineData(CipherMode.ECB)]
    [InlineData(CipherMode.CBC)]
    [InlineData(CipherMode.PCBC)]
    [InlineData(CipherMode.CFB)]
    [InlineData(CipherMode.OFB)]
    [InlineData(CipherMode.CTR)]
    [InlineData(CipherMode.RandomDelta)]
    public void Stream_Roundtrip(CipherMode mode)
    {
        var ctx = MakeCtx(mode, delta: mode == CipherMode.RandomDelta ? Delta : null);
        var data = new byte[1234];
        new Random((int)mode * 13 + 1).NextBytes(data);

        byte[] enc;
        using (var input = new MemoryStream(data))
        using (var output = new MemoryStream())
        {
            ctx.Encrypt(input, output);
            enc = output.ToArray();
        }

        byte[] dec;
        using (var input = new MemoryStream(enc))
        using (var output = new MemoryStream())
        {
            ctx.Decrypt(input, output);
            dec = output.ToArray();
        }

        Assert.Equal(data, dec);
    }

    [Fact]
    public void Stream_EncryptDecrypt_SmallBuffers()
    {
        var ctx = MakeCtx(CipherMode.CBC);
        var data = new byte[7];
        new Random(9).NextBytes(data);

        byte[] enc;
        using (var input = new MemoryStream(data))
        using (var output = new MemoryStream())
        {
            ctx.Encrypt(input, output);
            enc = output.ToArray();
        }

        byte[] dec;
        using (var input = new MemoryStream(enc))
        using (var output = new MemoryStream())
        {
            ctx.Decrypt(input, output);
            dec = output.ToArray();
        }

        Assert.Equal(data, dec);
    }

    [Fact]
    public void Stream_RepeatedCalls_ResetStateCorrectly()
    {
        var ctx = MakeCtx(CipherMode.CBC);
        var data = new byte[64];
        new Random(11).NextBytes(data);

        byte[] e1, e2;
        using (var i = new MemoryStream(data))
        using (var o = new MemoryStream()) { ctx.Encrypt(i, o); e1 = o.ToArray(); }
        using (var i = new MemoryStream(data))
        using (var o = new MemoryStream()) { ctx.Encrypt(i, o); e2 = o.ToArray(); }

        Assert.Equal(e1, e2);
    }

    [Fact]
    public void Stream_DecryptEmpty_Throws()
    {
        var ctx = MakeCtx(CipherMode.CBC);
        using var input = new MemoryStream(Array.Empty<byte>());
        using var output = new MemoryStream();
        Assert.Throws<ArgumentException>(() => ctx.Decrypt(input, output));
    }

    [Fact]
    public void Stream_DecryptNonAligned_Throws()
    {
        var ctx = MakeCtx(CipherMode.CBC);
        using var input = new MemoryStream(new byte[17]);
        using var output = new MemoryStream();
        Assert.Throws<ArgumentException>(() => ctx.Decrypt(input, output));
    }

    [Fact]
    public void EncryptStream_EqualsFileLikeApi()
    {
        var ctx = MakeCtx(CipherMode.CBC);
        var data = Enumerable.Range(0, 100).Select(i => (byte)i).ToArray();
        var a = ctx.EncryptStream(data);
        var b = ctx.EncryptStream(data);
        Assert.Equal(a, b);
    }

    [Fact]
    public void DecryptStream_Roundtrip()
    {
        var ctx = MakeCtx(CipherMode.CBC);
        var data = new byte[55];
        new Random(21).NextBytes(data);
        var enc = ctx.EncryptStream(data);
        var dec = ctx.DecryptStream(enc);
        Assert.Equal(data, dec);
    }

    [Fact]
    public async Task EncryptAsync_EqualsSync()
    {
        var ctx = MakeCtx(CipherMode.CBC);
        var data = new byte[100];
        new Random(31).NextBytes(data);
        ctx.Encrypt(data, out var sync);
        var async_ = await ctx.EncryptAsync(data);
        Assert.Equal(sync, async_);
    }

    // ---------- Файловое API ----------

    [Fact]
    public async Task FileApi_Roundtrip()
    {
        var ctx = MakeCtx(CipherMode.CBC);
        var data = new byte[333];
        new Random(41).NextBytes(data);

        var tmpIn = Path.GetTempFileName();
        var tmpEnc = Path.GetTempFileName();
        var tmpDec = Path.GetTempFileName();
        try
        {
            await File.WriteAllBytesAsync(tmpIn, data);
            await ctx.EncryptAsync(tmpIn, tmpEnc);
            await ctx.DecryptAsync(tmpEnc, tmpDec);
            var result = await File.ReadAllBytesAsync(tmpDec);
            Assert.Equal(data, result);
        }
        finally
        {
            File.Delete(tmpIn);
            File.Delete(tmpEnc);
            File.Delete(tmpDec);
        }
    }

    // ---------- Блочный размер 192/256 ----------

    [Theory]
    [InlineData(192)]
    [InlineData(256)]
    public void BlockSize192_256_Roundtrip(int blockBits)
    {
        int blockBytes = blockBits / 8;
        var cipher = new RijndaelCipher(new Gf256(0x11B), blockBits);
        var iv = new byte[blockBytes];
        new Random(blockBits).NextBytes(iv);
        var ctx = new SymmetricCryptoContext(
            cipher, Key128, CipherMode.CBC, PaddingMode.PKCS7, iv);

        var data = new byte[200];
        new Random(blockBits + 1).NextBytes(data);
        ctx.Encrypt(data, out var enc);
        Assert.Equal(0, enc.Length % blockBytes);
        ctx.Decrypt(enc, out var dec);
        Assert.Equal(data, dec);
    }
}