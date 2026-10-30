using System.Numerics;
using RSA.Core.Math;
using Xunit;

namespace RSA.Tests.Math;

public class ContinuedFractionsTests
{
    [Fact]
    public void GetConvergents_SmallFraction_ReturnsExpected()
    {
        // 17/13 = [1; 3, 4] → подходящие дроби: 1/1, 4/3, 17/13
        var convergents = ContinuedFractions.GetConvergents(17, 13);

        Assert.Equal(3, convergents.Count);
        Assert.Equal((BigInteger.One, BigInteger.One), convergents[0]);
        Assert.Equal((new BigInteger(4), new BigInteger(3)), convergents[1]);
        Assert.Equal((new BigInteger(17), new BigInteger(13)), convergents[^1]);
    }

    [Fact]
    public void GetConvergents_LastConvergent_EqualsOriginalFraction()
    {
        var convergents = ContinuedFractions.GetConvergents(355, 113); // π
        Assert.Equal(new BigInteger(355), convergents[^1].numerator);
        Assert.Equal(new BigInteger(113), convergents[^1].denominator);
    }

    [Fact]
    public void GetConvergents_Integer_ReturnsSingleConvergent()
    {
        var convergents = ContinuedFractions.GetConvergents(5, 1);
        Assert.Single(convergents);
        Assert.Equal((new BigInteger(5), BigInteger.One), convergents[0]);
    }

    [Fact]
    public void GetConvergents_ConvergentsAreReduced()
    {
        var convergents = ContinuedFractions.GetConvergents(12345, 6789);
        foreach (var (num, den) in convergents)
        {
            var g = NumberTheory.GcdClassic(num, den);
            Assert.Equal(BigInteger.One, g);
        }
    }
}