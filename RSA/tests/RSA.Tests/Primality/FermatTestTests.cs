using System.Numerics;
using RSA.Core.Primality;
using Xunit;

namespace RSA.Tests.Primality;

public class FermatTestTests
{
    [Theory]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(5)]
    [InlineData(97)]
    [InlineData(1009)]
    [InlineData(1000000007)]
    public void IsPrime_PrimeNumbers_ReturnsTrue(int p)
        => Assert.True(new FermatTest().IsPrime(p, 0.99));

    [Theory]
    [InlineData(1)]
    [InlineData(0)]
    [InlineData(-7)]
    [InlineData(4)]
    [InlineData(9)]
    [InlineData(100)]
    public void IsPrime_NonPrime_ReturnsFalse(int n)
        => Assert.False(new FermatTest().IsPrime(n, 0.99));

    [Fact]
    public void IsPrime_CarmichaelNumber_MayBeFalsePositive()
    {
        // 561 — число Кармайкла, тест Ферма может ошибочно принять его за простое.
        // Но при достаточной вероятности и нескольких итерациях часто всё же ловится.
        // Проверяем только, что метод не падает и возвращает bool.
        var result = new FermatTest().IsPrime(561, 0.9999);
        _ = result; // допускаем любой исход
    }
}