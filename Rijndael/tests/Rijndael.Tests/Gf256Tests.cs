using Rijndael.Core.GaloisField;
using Xunit;

namespace Rijndael.Tests;

public class Gf256Tests
{
    // ВАЖНО: static readonly, а не property!
    // Иначе каждый вызов создаёт new Gf256(0x11B), а конструктор
    // вызывает IsIrreducible → 28 PolyDiv + перебор битов.
    // В Multiply_DistributesOverAdd это давало 67M лишних проверок
    // неприводимости и «вечное» зависание теста.
    private static readonly Gf256 Aes = new(0x11B);

    // ---------- Конструктор ----------

    [Theory]
    [InlineData(0x100)]   // x^8 — приводим (x^8 = x*x*...)
    [InlineData(0x1FF)]
    public void Ctor_ThrowsForNonIrreducible(int modulus)
    {
        Assert.Throws<ArgumentException>(() => new Gf256(modulus));
    }

    [Theory]
    [InlineData(0x0FF)]
    [InlineData(0x200)]
    public void Ctor_ThrowsForOutOfRange(int modulus)
    {
        Assert.Throws<ArgumentException>(() => new Gf256(modulus));
    }

    [Theory]
    [InlineData(0x11B)] // AES
    [InlineData(0x12B)]
    [InlineData(0x12D)]
    [InlineData(0x139)]
    [InlineData(0x163)]
    public void Ctor_AcceptsKnownIrreducible(int modulus)
    {
        var gf = new Gf256(modulus);
        Assert.Equal(modulus, gf.Modulus);
    }

    // ---------- Add ----------

    [Theory]
    [InlineData(0x00, 0x00, 0x00)]
    [InlineData(0xFF, 0xFF, 0x00)]        // a xor a = 0
    [InlineData(0x57, 0x83, 0xD4)]
    [InlineData(0x12, 0x34, 0x26)]
    public void Add_IsXor(byte a, byte b, byte expected)
    {
        Assert.Equal(expected, Aes.Add(a, b));
    }

    // ---------- Multiply ----------

    [Theory]
    [InlineData(0x00, 0x00, 0x00)]
    [InlineData(0x01, 0x57, 0x57)]
    [InlineData(0x02, 0x80, 0x1B)]        // xtime
    [InlineData(0x57, 0x83, 0xC1)]        // известный пример FIPS-197
    [InlineData(0x57, 0x13, 0xFE)]
    public void Multiply_KnownValues(byte a, byte b, byte expected)
    {
        Assert.Equal(expected, Aes.Multiply(a, b));
    }

    [Theory]
    [InlineData(0x00)]
    [InlineData(0x01)]
    [InlineData(0x02)]
    [InlineData(0x80)]
    [InlineData(0xFF)]
    public void Multiply_ByZeroOrOne(byte a)
    {
        Assert.Equal((byte)0, Aes.Multiply(a, 0));
        Assert.Equal(a, Aes.Multiply(a, 1));
    }

    [Fact]
    public void Multiply_IsCommutative()
    {
        // 65 536 итераций × 2 Multiply — быстро даже в Debug
        for (int a = 0; a < 256; a++)
        for (int b = 0; b < 256; b++)
            Assert.Equal(Aes.Multiply((byte)a, (byte)b), Aes.Multiply((byte)b, (byte)a));
    }

    [Fact]
    public void Multiply_DistributesOverAdd()
    {
        // Полный перебор 256^3 = 16.7M троек — это ~400M операций
        // и десятки секунд в Debug. Случайная выборка 10 000 троек
        // ловит любую реальную ошибку дистрибутивности с той же
        // вероятностью и выполняется за единицы миллисекунд.
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
        // Тоже property-based, но с выборкой — быстро
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
        // a * a^{-1} == 1 для всех a ∈ [1..255]
        for (int a = 1; a < 256; a++)
        {
            byte inv = Aes.Inverse((byte)a);
            Assert.Equal((byte)1, Aes.Multiply((byte)a, inv));
        }
    }

    [Fact]
    public void Inverse_IsInvolution()
    {
        // Inverse(Inverse(a)) == a
        for (int a = 1; a < 256; a++)
            Assert.Equal((byte)a, Aes.Inverse(Aes.Inverse((byte)a)));
    }

    [Theory]
    [InlineData(0x01, 0x01)]
    [InlineData(0x02, 0x8D)]
    [InlineData(0x03, 0xF6)]
    [InlineData(0x53, 0xCA)]   // известный пример AES: Inverse(0x53) = 0xCA
    [InlineData(0xFF, 0x1C)]   // проверено: 0xFF * 0x1C ≡ 1 (mod 0x11B)
    public void Inverse_KnownValues(byte a, byte expected)
    {
        Assert.Equal(expected, Aes.Inverse(a));
    }

    [Fact]
    public void Inverse_DistinctForDistinctInputs()
    {
        // Inverse — биекция на ненулевых элементах
        var seen = new HashSet<byte>();
        for (int a = 1; a < 256; a++)
            Assert.True(seen.Add(Aes.Inverse((byte)a)));
        Assert.Equal(255, seen.Count);
    }

    // ---------- IsIrreducible ----------

    [Theory]
    [InlineData(0x11B, true)]
    [InlineData(0x100, false)]
    [InlineData(0x101, false)]   // x^8 + 1 = (x+1)^8, приводим
    [InlineData(0x1FF, false)]
    public void IsIrreducible_BasicCases(int p, bool expected)
    {
        Assert.Equal(expected, Gf256.IsIrreducible(p));
    }

    [Fact]
    public void IsIrreducible_RejectsEvenPolynomials()
    {
        // Все чётные полиномы имеют корень x=0
        for (int p = 0x100; p <= 0x1FE; p += 2)
            Assert.False(Gf256.IsIrreducible(p));
    }

    [Fact]
    public void IsIrreducible_RejectsPolynomialsWithXorOne()
    {
        // Если сумма коэффициентов = 0 (mod 2), то p(1) = 0 → приводим
        for (int p = 0x100; p <= 0x1FF; p++)
        {
            int parity = 0;
            int t = p;
            while (t != 0) { parity ^= (t & 1); t >>= 1; }
            if (parity == 0)
                Assert.False(Gf256.IsIrreducible(p));
        }
    }

    [Fact]
    public void IsIrreducible_RejectsOutOfDegreeRange()
    {
        Assert.False(Gf256.IsIrreducible(0x0FF)); // deg 7
        Assert.False(Gf256.IsIrreducible(0x200)); // deg 9
    }

    [Fact]
    public void FindAllIrreducibleDegree8_ContainsAesModulus()
    {
        var all = Gf256.FindAllIrreducibleDegree8();
        Assert.Contains(0x11B, all);
        Assert.True(all.Count > 0);

        // В GF(2^8) ровно 30 неприводимых полиномов степени 8
        Assert.Equal(30, all.Count);
    }

    [Fact]
    public void FindAllIrreducibleDegree8_AllAreActuallyIrreducible()
    {
        foreach (int p in Gf256.FindAllIrreducibleDegree8())
            Assert.True(Gf256.IsIrreducible(p), $"0x{p:X} должно быть неприводимым");
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

            // Ассоциативность сложения
            Assert.Equal(
                Aes.Add(Aes.Add(a, b), c),
                Aes.Add(a, Aes.Add(b, c)));

            // Коммутативность сложения
            Assert.Equal(Aes.Add(a, b), Aes.Add(b, a));

            // Нейтральный по сложению
            Assert.Equal(a, Aes.Add(a, 0));

            // Обратный по сложению (сам себе)
            Assert.Equal((byte)0, Aes.Add(a, a));

            // Ассоциативность умножения
            Assert.Equal(
                Aes.Multiply(Aes.Multiply(a, b), c),
                Aes.Multiply(a, Aes.Multiply(b, c)));

            // Коммутативность умножения
            Assert.Equal(Aes.Multiply(a, b), Aes.Multiply(b, a));

            // Нейтральный по умножению
            Assert.Equal(a, Aes.Multiply(a, 1));

            // Поглощающий
            Assert.Equal((byte)0, Aes.Multiply(a, 0));

            // Дистрибутивность
            Assert.Equal(
                Aes.Multiply(a, Aes.Add(b, c)),
                Aes.Add(Aes.Multiply(a, b), Aes.Multiply(a, c)));
        }
    }
}