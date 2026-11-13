using Rijndael.Core.GaloisField;
using Xunit;

namespace Rijndael.Tests;

public class Gf256Tests
{
    private static readonly Gf256 Aes = new(0x1B);

    // ---------- Конструктор ----------

    [Theory]
    [InlineData((byte)0x00)]
    [InlineData((byte)0x01)]
    [InlineData((byte)0xFF)]
    public void Ctor_ThrowsForNonIrreducible(byte modulus)
    {
        Assert.Throws<ArgumentException>(() => new Gf256(modulus));
    }

    [Theory]
    [InlineData((byte)0x1B)] // AES
    [InlineData((byte)0x2B)]
    [InlineData((byte)0x2D)]
    [InlineData((byte)0x39)]
    [InlineData((byte)0x63)]
    public void Ctor_AcceptsKnownIrreducible(byte modulus)
    {
        var gf = new Gf256(modulus);
        Assert.Equal(modulus, gf.Modulus);
    }

    // ---------- Add ----------

    [Theory]
    [InlineData((byte)0x00, (byte)0x00, (byte)0x00)]
    [InlineData((byte)0xFF, (byte)0xFF, (byte)0x00)]
    [InlineData((byte)0x57, (byte)0x83, (byte)0xD4)]
    [InlineData((byte)0x12, (byte)0x34, (byte)0x26)]
    public void Add_IsXor(byte a, byte b, byte expected)
    {
        Assert.Equal(expected, Aes.Add(a, b));
    }

    // ---------- Multiply ----------

    [Theory]
    [InlineData((byte)0x00, (byte)0x00, (byte)0x00)]
    [InlineData((byte)0x01, (byte)0x57, (byte)0x57)]
    [InlineData((byte)0x02, (byte)0x80, (byte)0x1B)]
    [InlineData((byte)0x57, (byte)0x83, (byte)0xC1)]
    [InlineData((byte)0x57, (byte)0x13, (byte)0xFE)]
    public void Multiply_KnownValues(byte a, byte b, byte expected)
    {
        Assert.Equal(expected, Aes.Multiply(a, b));
    }

    [Theory]
    [InlineData((byte)0x00)]
    [InlineData((byte)0x01)]
    [InlineData((byte)0x02)]
    [InlineData((byte)0x80)]
    [InlineData((byte)0xFF)]
    public void Multiply_ByZeroOrOne(byte a)
    {
        Assert.Equal((byte)0, Aes.Multiply(a, 0));
        Assert.Equal(a, Aes.Multiply(a, 1));
    }

    [Fact]
    public void Multiply_IsCommutative()
    {
        for (int a = 0; a < 256; a++)
        for (int b = 0; b < 256; b++)
            Assert.Equal(Aes.Multiply((byte)a, (byte)b), Aes.Multiply((byte)b, (byte)a));
    }

    [Fact]
    public void Multiply_DistributesOverAdd()
    {
        var rnd = new Random(42);
        for (int i = 0; i < 10_000; i++)
        {
            byte a = (byte)rnd.Next(256);
            byte b = (byte)rnd.Next(256);
            byte c = (byte)rnd.Next(256);

            byte lhs = Aes.Multiply(a, Aes.Add(b, c));
            byte rhs = Aes.Add(Aes.Multiply(a, b), Aes.Multiply(a, c));
            Assert.Equal(lhs, rhs);
        }
    }

    [Fact]
    public void Multiply_Associative()
    {
        var rnd = new Random(43);
        for (int i = 0; i < 10_000; i++)
        {
            byte a = (byte)rnd.Next(256);
            byte b = (byte)rnd.Next(256);
            byte c = (byte)rnd.Next(256);

            byte lhs = Aes.Multiply(Aes.Multiply(a, b), c);
            byte rhs = Aes.Multiply(a, Aes.Multiply(b, c));
            Assert.Equal(lhs, rhs);
        }
    }

    // ---------- Inverse ----------

    [Fact]
    public void Inverse_Zero_Throws()
    {
        Assert.Throws<InvalidOperationException>(() => Aes.Inverse(0));
    }

    [Fact]
    public void Inverse_AllNonZeroElements_HaveInverse()
    {
        for (int a = 1; a < 256; a++)
        {
            byte inv = Aes.Inverse((byte)a);
            Assert.Equal((byte)1, Aes.Multiply((byte)a, inv));
        }
    }

    [Fact]
    public void Inverse_IsInvolution()
    {
        for (int a = 1; a < 256; a++)
            Assert.Equal((byte)a, Aes.Inverse(Aes.Inverse((byte)a)));
    }

    [Theory]
    [InlineData((byte)0x01, (byte)0x01)]
    [InlineData((byte)0x02, (byte)0x8D)]
    [InlineData((byte)0x03, (byte)0xF6)]
    [InlineData((byte)0x53, (byte)0xCA)]
    [InlineData((byte)0xFF, (byte)0x1C)]
    public void Inverse_KnownValues(byte a, byte expected)
    {
        Assert.Equal(expected, Aes.Inverse(a));
    }

    [Fact]
    public void Inverse_DistinctForDistinctInputs()
    {
        var seen = new HashSet<byte>();
        for (int a = 1; a < 256; a++)
            Assert.True(seen.Add(Aes.Inverse((byte)a)));
        Assert.Equal(255, seen.Count);
    }

    // ---------- IsIrreducible ----------

    [Theory]
    [InlineData((byte)0x1B, true)]
    [InlineData((byte)0x00, false)]
    [InlineData((byte)0x01, false)]
    [InlineData((byte)0xFF, false)]
    public void IsIrreducible_BasicCases(byte p, bool expected)
    {
        Assert.Equal(expected, Gf256.IsIrreducible(p));
    }

    [Fact]
    public void IsIrreducible_RejectsEvenPolynomials()
    {
        for (int m = 0x00; m <= 0xFE; m += 2)
            Assert.False(Gf256.IsIrreducible((byte)m));
    }

    [Fact]
    public void IsIrreducible_RejectsPolynomialsWithXorOne()
    {
        for (int m = 0x00; m <= 0xFF; m++)
        {
            int p = 0x100 | m;
            int parity = 0;
            int t = p;
            while (t != 0) { parity ^= (t & 1); t >>= 1; }
            if (parity == 0)
                Assert.False(Gf256.IsIrreducible((byte)m));
        }
    }

    [Fact]
    public void FindAllIrreducibleDegree8_ContainsAesModulus()
    {
        var all = Gf256.FindAllIrreducibleDegree8();
        Assert.Contains((byte)0x1B, all);
    }

    [Fact]
    public void FindAllIrreducibleDegree8_AllAreActuallyIrreducible()
    {
        foreach (byte p in Gf256.FindAllIrreducibleDegree8())
            Assert.True(Gf256.IsIrreducible(p), $"0x{0x100 | p:X} должно быть неприводимым");
    }

    // ---------- Свойства поля ----------

    [Fact]
    public void Field_Axioms_HoldWithSampling()
    {
        var rnd = new Random(7);
        for (int i = 0; i < 1000; i++)
        {
            byte a = (byte)rnd.Next(256);
            byte b = (byte)rnd.Next(256);
            byte c = (byte)rnd.Next(256);

            Assert.Equal(
                Aes.Add(Aes.Add(a, b), c),
                Aes.Add(a, Aes.Add(b, c)));

            Assert.Equal(Aes.Add(a, b), Aes.Add(b, a));

            Assert.Equal(a, Aes.Add(a, 0));

            Assert.Equal((byte)0, Aes.Add(a, a));

            Assert.Equal(
                Aes.Multiply(Aes.Multiply(a, b), c),
                Aes.Multiply(a, Aes.Multiply(b, c)));

            Assert.Equal(Aes.Multiply(a, b), Aes.Multiply(b, a));

            Assert.Equal(a, Aes.Multiply(a, 1));

            Assert.Equal((byte)0, Aes.Multiply(a, 0));

            Assert.Equal(
                Aes.Multiply(a, Aes.Add(b, c)),
                Aes.Add(Aes.Multiply(a, b), Aes.Multiply(a, c)));
        }
    }
}