using Rijndael.Core.GaloisField;
using Rijndael.Core.Rijndael;
using Xunit;

namespace Rijndael.Tests;

public class RijndaelKeySchedulerTests
{
    // Эталонный вектор FIPS-197, Приложение A.1 (AES-128)
    [Fact]
    public void Aes128_ProducesKnownRoundKeys()
    {
        var gf = new Gf256(0x1B);
        var sbox = new SBoxGenerator(gf);
        var scheduler = new RijndaelKeyScheduler(gf, sbox, 4);

        var key = new byte[]
        {
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
        };

        var rk = scheduler.GenerateRoundKeys(key);
        Assert.Equal(11, rk.Length);

        // FIPS-197 A.1 — полный эталон
        var expected = new byte[11][]
        {
            new byte[] { 0x2B,0x7E,0x15,0x16,0x28,0xAE,0xD2,0xA6,0xAB,0xF7,0x15,0x88,0x09,0xCF,0x4F,0x3C },
            new byte[] { 0xA0,0xFA,0xFE,0x17,0x88,0x54,0x2C,0xB1,0x23,0xA3,0x39,0x39,0x2A,0x6C,0x76,0x05 },
            new byte[] { 0xF2,0xC2,0x95,0xF2,0x7A,0x96,0xB9,0x43,0x59,0x35,0x80,0x7A,0x73,0x59,0xF6,0x7F },
            new byte[] { 0x3D,0x80,0x47,0x7D,0x47,0x16,0xFE,0x3E,0x1E,0x23,0x7E,0x44,0x6D,0x7A,0x88,0x3B },
            new byte[] { 0xEF,0x44,0xA5,0x41,0xA8,0x52,0x5B,0x7F,0xB6,0x71,0x25,0x3B,0xDB,0x0B,0xAD,0x00 },
            new byte[] { 0xD4,0xD1,0xC6,0xF8,0x7C,0x83,0x9D,0x87,0xCA,0xF2,0xB8,0xBC,0x11,0xF9,0x15,0xBC },
            new byte[] { 0x6D,0x88,0xA3,0x7A,0x11,0x0B,0x3E,0xFD,0xDB,0xF9,0x86,0x41,0xCA,0x00,0x93,0xFD },
            new byte[] { 0x4E,0x54,0xF7,0x0E,0x5F,0x5F,0xC9,0xF3,0x84,0xA6,0x4F,0xB2,0x4E,0xA6,0xDC,0x4F },
            new byte[] { 0xEA,0xD2,0x73,0x21,0xB5,0x8D,0xBA,0xD2,0x31,0x2B,0xF5,0x60,0x7F,0x8D,0x29,0x2F },
            new byte[] { 0xAC,0x77,0x66,0xF3,0x19,0xFA,0xDC,0x21,0x28,0xD1,0x29,0x41,0x57,0x5C,0x00,0x6E },
            new byte[] { 0xD0,0x14,0xF9,0xA8,0xC9,0xEE,0x25,0x89,0xE1,0x3F,0x0C,0xC8,0xB6,0x63,0x0C,0xA6 }
        };

        for (int r = 0; r <= 10; r++)
        {
            for (int i = 0; i < 16; i++)
            {
                Assert.True(expected[r][i] == rk[r][i],
                    $"rk[{r}][{i}]: expected 0x{expected[r][i]:X2}, got 0x{rk[r][i]:X2} (round {r}, byte {i})");
            }
        }
    }

    [Theory]
    [InlineData(16, 4, 10)] // AES-128: Nb=4, Nk=4 -> Nr=10
    [InlineData(24, 6, 12)] // AES-192: Nb=4, Nk=6 -> Nr=12
    [InlineData(32, 8, 14)] // AES-256: Nb=4, Nk=8 -> Nr=14
    public void Aes_KeySizes_ProduceExpectedNr(int keyLen, int nk, int expectedNr)
    {
        Assert.Equal(nk, keyLen / 4);
        
        var gf = new Gf256(0x1B);
        var sbox = new SBoxGenerator(gf);
        var scheduler = new RijndaelKeyScheduler(gf, sbox, 4);
        var key = new byte[keyLen];

        var rk = scheduler.GenerateRoundKeys(key);
        Assert.Equal(expectedNr + 1, rk.Length);
        Assert.All(rk, r => Assert.Equal(16, r.Length));
    }

    [Fact]
    public void BlockSize192_ChangesNr()
    {
        var gf = new Gf256(0x1B);
        var sbox = new SBoxGenerator(gf);
        // Nb=6, Nk=4 -> Nr = max(6,4)+6 = 12
        var scheduler = new RijndaelKeyScheduler(gf, sbox, 6);
        var key = new byte[16];

        var rk = scheduler.GenerateRoundKeys(key);
        Assert.Equal(13, rk.Length);
        Assert.All(rk, r => Assert.Equal(24, r.Length));
    }

    [Fact]
    public void BlockSize256_ChangesNr()
    {
        var gf = new Gf256(0x1B);
        var sbox = new SBoxGenerator(gf);
        // Nb=8, Nk=4 -> Nr = max(8,4)+6 = 14
        var scheduler = new RijndaelKeyScheduler(gf, sbox, 8);
        var key = new byte[16];

        var rk = scheduler.GenerateRoundKeys(key);
        Assert.Equal(15, rk.Length);
        Assert.All(rk, r => Assert.Equal(32, r.Length));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(5)]
    [InlineData(7)]
    [InlineData(9)]
    [InlineData(15)]
    public void InvalidNb_Throws(int nb)
    {
        var gf = new Gf256(0x1B);
        var sbox = new SBoxGenerator(gf);
        Assert.Throws<ArgumentException>(() => new RijndaelKeyScheduler(gf, sbox, nb));
    }

    [Fact]
    public void InvalidKeyLength_Throws()
    {
        var gf = new Gf256(0x1B);
        var sbox = new SBoxGenerator(gf);
        var scheduler = new RijndaelKeyScheduler(gf, sbox, 4);
        Assert.Throws<ArgumentException>(() => scheduler.GenerateRoundKeys(new byte[10]));
    }
}