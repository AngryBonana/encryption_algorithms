using System.Numerics;
using RSA.Core.Math;
using Xunit;

namespace RSA.Tests.Math;

public class NumberTheoryTests
{
    // ---------- Символ Лежандра ----------
    [Theory]
    [InlineData(1, 7, 1)]
    [InlineData(2, 7, 1)]
    [InlineData(3, 7, -1)]
    [InlineData(4, 7, 1)]
    [InlineData(5, 7, -1)]
    [InlineData(6, 7, -1)]
    [InlineData(0, 7, 0)]
    public void LegendreSymbol_KnownValues(int a, int p, int expected)
        => Assert.Equal(expected, NumberTheory.LegendreSymbol(a, p));

    [Fact]
    public void LegendreSymbol_QuadraticResidue_ReturnsOne()
    {
        // 3^2 = 9 ≡ 2 mod 7 → 2 — квадратичный вычет
        Assert.Equal(1, NumberTheory.LegendreSymbol(2, 7));
    }

    [Fact]
    public void LegendreSymbol_NegativeA_Works()
    {
        // (-1/7) = (-1)^((7-1)/2) = -1
        Assert.Equal(-1, NumberTheory.LegendreSymbol(-1, 7));
    }

    // ---------- Символ Якоби ----------
    [Theory]
    [InlineData(1, 15, 1)]
    [InlineData(2, 15, 1)]
    [InlineData(4, 15, 1)]
    [InlineData(7, 15, -1)]
    [InlineData(8, 15, 1)]
    [InlineData(11, 15, -1)]
    [InlineData(0, 15, 0)]
    public void JacobiSymbol_KnownValues(int a, int n, int expected)
        => Assert.Equal(expected, NumberTheory.JacobiSymbol(a, n));

    [Fact]
    public void JacobiSymbol_ForPrime_MatchesLegendre()
    {
        int p = 101;
        for (int a = 1; a < p; a++)
            Assert.Equal(NumberTheory.LegendreSymbol(a, p), NumberTheory.JacobiSymbol(a, p));
    }

    [Fact]
    public void JacobiSymbol_EvenN_Throws()
        => Assert.Throws<ArgumentException>(() => NumberTheory.JacobiSymbol(5, 10));

    [Fact]
    public void JacobiSymbol_NonPositiveN_Throws()
        => Assert.Throws<ArgumentException>(() => NumberTheory.JacobiSymbol(5, 0));

    // ---------- НОД: три алгоритма дают одинаковый результат ----------
    [Theory]
    [InlineData(12, 18, 6)]
    [InlineData(100, 75, 25)]
    [InlineData(17, 13, 1)]
    [InlineData(0, 5, 5)]
    [InlineData(5, 0, 5)]
    [InlineData(0, 0, 0)]
    [InlineData(-12, 18, 6)]
    [InlineData(12, -18, 6)]
    [InlineData(123456, 7890, 6)]
    public void Gcd_AllAlgorithmsAgree(int a, int b, int expected)
    {
        Assert.Equal(expected, (int)NumberTheory.GcdClassic(a, b));
        Assert.Equal(expected, (int)NumberTheory.GcdBinary(a, b));
        Assert.Equal(expected, (int)NumberTheory.GcdExtended(a, b).g);
    }

    // ---------- Расширенный Евклид: ax + by = g ----------
    [Theory]
    [InlineData(240, 46)]
    [InlineData(123456, 7890)]
    [InlineData(17, 13)]
    [InlineData(1000000007, 998244353)]
    public void GcdExtended_BezoutIdentity(long a, long b)
    {
        var (g, x, y) = NumberTheory.GcdExtended(a, b);
        Assert.Equal(g, a * x + b * y);
        Assert.Equal(NumberTheory.GcdClassic(a, b), g);
    }

    // ---------- ModPow ----------
    [Theory]
    [InlineData(2, 10, 1000, 24)]
    [InlineData(3, 0, 7, 1)]
    [InlineData(5, 1, 7, 5)]
    [InlineData(2, 100, 1000000007, 976371285)]
    [InlineData(7, 5, 13, 11)]
    public void ModPow_KnownValues(long b, long e, long m, long expected)
        => Assert.Equal(new BigInteger(expected), NumberTheory.ModPow(b, e, m));

    [Fact]
    public void ModPow_ModulusOne_ReturnsZero()
        => Assert.Equal(BigInteger.Zero, NumberTheory.ModPow(5, 10, 1));

    // ---------- Функция Эйлера: три способа ----------
    [Theory]
    [InlineData(1, 1)]
    [InlineData(2, 1)]
    [InlineData(6, 2)]
    [InlineData(9, 6)]
    [InlineData(12, 4)]
    [InlineData(36, 12)]
    [InlineData(97, 96)]
    public void EulerPhi_AllMethodsAgree(int n, int expected)
    {
        Assert.Equal(expected, (int)NumberTheory.EulerPhiByDefinition(n));
        Assert.Equal(expected, (int)NumberTheory.EulerPhiByFactorization(n));
        Assert.Equal(expected, NumberTheory.EulerPhiByDft(n), 6); // DFT — с плавающей точкой
    }

    [Fact]
    public void EulerPhi_Prime_ReturnsNMinusOne()
    {
        Assert.Equal(1000000006, (int)NumberTheory.EulerPhiByFactorization(1000000007));
    }

    // ---------- Функция Кармайкла ----------
    [Theory]
    [InlineData(1, 1)]
    [InlineData(2, 1)]
    [InlineData(8, 2)]
    [InlineData(15, 4)]
    [InlineData(16, 4)]
    [InlineData(36, 6)]
    [InlineData(97, 96)]   // простое → lambda = p-1
    public void CarmichaelLambda_KnownValues(int n, int expected)
        => Assert.Equal(expected, (int)NumberTheory.CarmichaelLambda(n));

    [Fact]
    public void CarmichaelLambda_DividesEulerPhi()
    {
        for (int n = 2; n <= 200; n++)
        {
            var lambda = NumberTheory.CarmichaelLambda(n);
            var phi = NumberTheory.EulerPhiByFactorization(n);
            Assert.Equal(0, phi % lambda);
        }
    }

    // ---------- Вспомогательные ----------
    [Fact]
    public void Lcm_KnownValues()
    {
        Assert.Equal(12, (int)NumberTheory.Lcm(4, 6));
        Assert.Equal(36, (int)NumberTheory.Lcm(12, 18));
    }

    [Theory]
    [InlineData(12, new[] { 2, 2, 3 })]
    [InlineData(36, new[] { 2, 2, 3, 3 })]
    [InlineData(97, new[] { 97 })]
    public void GetPrimeFactors_ReturnsCorrectMultiplicities(int n, int[] primes)
    {
        var factors = NumberTheory.GetPrimeFactors(n);
        var expanded = factors.SelectMany(kv => Enumerable.Repeat((int)kv.Key, kv.Value)).OrderBy(x => x).ToArray();
        Assert.Equal(primes.OrderBy(x => x), expanded);
    }
}