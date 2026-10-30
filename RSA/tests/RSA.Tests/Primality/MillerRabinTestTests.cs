using RSA.Core.Primality;
using Xunit;

namespace RSA.Tests.Primality;

public class MillerRabinTestTests
{
    [Theory]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(5)]
    [InlineData(97)]
    [InlineData(1009)]
    [InlineData(1000000007)]
    public void IsPrime_PrimeNumbers_ReturnsTrue(int p)
        => Assert.True(new MillerRabinTest().IsPrime(p, 0.99));

    [Theory]
    [InlineData(1)]
    [InlineData(0)]
    [InlineData(4)]
    [InlineData(9)]
    [InlineData(15)]
    [InlineData(100)]
    [InlineData(561)]
    [InlineData(1105)]
    public void IsPrime_NonPrime_ReturnsFalse(int n)
        => Assert.False(new MillerRabinTest().IsPrime(n, 0.99));

    [Fact]
    public void IsPrime_WithHighProbability_StillCorrect()
    {
        var mr = new MillerRabinTest();
        Assert.True(mr.IsPrime(1000000007, 0.9999999));
        Assert.False(mr.IsPrime(1000000009 * 3L, 0.9999999));
    }

    [Fact]
    public void TemplateMethod_BaseClassControlsProbabilityLoop()
    {
        // Проверяем, что базовый класс реализует шаблонный метод:
        // при разных minProbability корректность сохраняется
        var mr = new MillerRabinTest();
        Assert.True(mr.IsPrime(97, 0.5));
        Assert.True(mr.IsPrime(97, 0.99));
        Assert.True(mr.IsPrime(97, 0.9999));
    }
}