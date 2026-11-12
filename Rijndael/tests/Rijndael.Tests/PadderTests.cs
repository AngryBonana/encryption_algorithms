using Rijndael.Core.Padding;
using CryptographicException = System.Security.Cryptography.CryptographicException;
using Xunit;

namespace Rijndael.Tests;

public class PadderTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(256)]
    public void Pad_ThrowsOnBadBlockSize(int bs)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => Padder.Pad(new byte[1], bs, PaddingMode.PKCS7));
    }

    [Fact]
    public void Pad_NullData_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => Padder.Pad(null!, 16, PaddingMode.PKCS7));
    }

    [Fact]
    public void Unpad_NullData_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => Padder.Unpad(null!, PaddingMode.PKCS7));
    }

    [Theory]
    [InlineData(0, 16, 16)]
    [InlineData(1, 16, 16)]
    [InlineData(15, 16, 16)]
    [InlineData(16, 16, 32)]
    [InlineData(17, 16, 32)]
    public void Pad_Pkcs7_ProducesBlockMultiple(int dataLen, int bs, int expected)
    {
        var data = new byte[dataLen];
        var padded = Padder.Pad(data, bs, PaddingMode.PKCS7);
        Assert.Equal(expected, padded.Length);
        byte padByte = (byte)(padded.Length - dataLen);
        for (int i = dataLen; i < padded.Length; i++)
            Assert.Equal(padByte, padded[i]);
    }

    [Fact]
    public void Pad_Pkcs7_ZeroLength_AddsFullBlock()
    {
        var padded = Padder.Pad(Array.Empty<byte>(), 16, PaddingMode.PKCS7);
        Assert.Equal(16, padded.Length);
        Assert.All(padded, b => Assert.Equal(16, b));
    }

    [Fact]
    public void Pad_AnsiX923_LastByteIsLength()
    {
        var data = new byte[5];
        var padded = Padder.Pad(data, 16, PaddingMode.ANSI_X923);
        Assert.Equal(16, padded.Length);
        Assert.Equal(11, padded[^1]);
        for (int i = 5; i < 15; i++)
            Assert.Equal(0, padded[i]);
    }

    [Fact]
    public void Pad_Iso10126_LastByteIsLength()
    {
        var data = new byte[5];
        var padded = Padder.Pad(data, 16, PaddingMode.ISO10126);
        Assert.Equal(16, padded.Length);
        Assert.Equal(11, padded[^1]);
    }

    [Fact]
    public void Pad_Zeros_WhenAligned_ReturnsClone()
    {
        var data = new byte[16];
        data[15] = 5;
        var padded = Padder.Pad(data, 16, PaddingMode.Zeros);
        Assert.Equal(data, padded);
        Assert.NotSame(data, padded);
    }

    [Fact]
    public void Pad_Zeros_WhenMisaligned_PadsWithZero()
    {
        var data = new byte[5];
        var padded = Padder.Pad(data, 16, PaddingMode.Zeros);
        Assert.Equal(16, padded.Length);
        for (int i = 5; i < 16; i++)
            Assert.Equal(0, padded[i]);
    }

    [Theory]
    [InlineData(PaddingMode.PKCS7)]
    [InlineData(PaddingMode.ANSI_X923)]
    [InlineData(PaddingMode.ISO10126)]
    [InlineData(PaddingMode.Zeros)]
    public void PadUnpad_Roundtrip(PaddingMode mode)
    {
        var data = new byte[] { 1, 2, 3, 4, 5 };
        var padded = Padder.Pad(data, 16, mode);
        var unpadded = Padder.Unpad(padded, mode);
        Assert.Equal(data, unpadded);
    }

    [Fact]
    public void Unpad_Pkcs7_InvalidPad_Throws()
    {
        var bad = new byte[16];
        bad[^1] = 4; // но остальные — нули, не 4
        Assert.Throws<CryptographicException>(() => Padder.Unpad(bad, PaddingMode.PKCS7));
    }

    [Fact]
    public void Unpad_Pkcs7_ZeroLength_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => Padder.Unpad(Array.Empty<byte>(), PaddingMode.PKCS7));
    }

    [Fact]
    public void Unpad_AnsiX923_Invalid_Throws()
    {
        var bad = new byte[16];
        bad[^1] = 4;
        bad[^2] = 1; // должен быть 0
        Assert.Throws<CryptographicException>(() => Padder.Unpad(bad, PaddingMode.ANSI_X923));
    }

    [Fact]
    public void Unpad_PadLengthTooLarge_Throws()
    {
        var bad = new byte[4];
        bad[^1] = 10;
        Assert.Throws<CryptographicException>(() => Padder.Unpad(bad, PaddingMode.PKCS7));
    }

    [Fact]
    public void Unpad_Zeros_TrimsTrailingZeros()
    {
        var data = new byte[] { 1, 2, 3, 0, 0 };
        var result = Padder.Unpad(data, PaddingMode.Zeros);
        Assert.Equal(new byte[] { 1, 2, 3 }, result);
    }
}