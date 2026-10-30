using RSA.Core.Primality;
using Xunit;

namespace RSA.Tests.Primality;

public class SolovayStrassenTestTests
{
    [Theory]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(5)]
    [InlineData(97)]
    [InlineData(1009)]
    [InlineData(1000000007)]
    public void IsPrime_PrimeNumbers_ReturnsTrue(int p)
        => Assert.True(new SolovayStrassenTest().IsPrime(p, 0.99));

    [Theory]
    [InlineData(1)]
    [InlineData(0)]
    [InlineData(4)]
    [InlineData(9)]
    [InlineData(15)]
    [InlineData(100)]
    public void IsPrime_NonPrime_ReturnsFalse(int n)
        => Assert.False(new SolovayStrassenTest().IsPrime(n, 0.99));

    [Fact]
    public void IsPrime_Carmichael561_DetectedAsComposite()
    {
        // Тест Соловея-Штрассена надёжнее Ферма для чисел Кармайкла
        Assert.False(new SolovayStrassenTest().IsPrime(561, 0.9999));
    }
}