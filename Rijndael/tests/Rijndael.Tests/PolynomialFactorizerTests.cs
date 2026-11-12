using Rijndael.Core.GaloisField;
using Xunit;

namespace Rijndael.Tests;

public class PolynomialFactorizerTests
{
    [Fact]
    public void Factorize_Zero_Throws()
    {
        Assert.Throws<ArgumentException>(() => PolynomialFactorizer.Factorize(0));
    }

    [Fact]
    public void Factorize_One_ReturnsEmpty()
    {
        var result = PolynomialFactorizer.Factorize(1);
        Assert.Empty(result);
    }

    [Theory]
    [InlineData(0x02)] // x
    [InlineData(0x03)] // x+1
    [InlineData(0x07)] // x^2+x+1
    public void Factorize_Irreducible_ReturnsItself(int p)
    {
        var result = PolynomialFactorizer.Factorize(p);
        Assert.Single(result);
        Assert.Equal(p, result[0].Factor);
        Assert.Equal(1, result[0].Power);
    }

    [Fact]
    public void Factorize_Square_ReturnsPower2()
    {
        // (x+1)^2 = x^2 + 1 = 0b101 = 0x05
        var result = PolynomialFactorizer.Factorize(0x05);
        Assert.Single(result);
        Assert.Equal(0x03, result[0].Factor);
        Assert.Equal(2, result[0].Power);
    }

    [Fact]
    public void Factorize_Product_ReturnsBothFactors()
    {
        // x * (x+1) = x^2 + x = 0b110 = 0x06
        var result = PolynomialFactorizer.Factorize(0x06);
        Assert.Equal(2, result.Count);
    }

    [Fact]
    public void Factorize_AesModulus_IsIrreducible()
    {
        // 0x11B — неприводимый
        var result = PolynomialFactorizer.Factorize(0x11B);
        Assert.Single(result);
        Assert.Equal(0x11B, result[0].Factor);
    }

    [Fact]
    public void Factorize_CubeOfXPlus1()
    {
        // (x+1)^3 = x^3 + x^2 + x + 1 = 0b1111 = 0x0F
        var result = PolynomialFactorizer.Factorize(0x0F);
        Assert.Single(result);
        Assert.Equal(0x03, result[0].Factor);
        Assert.Equal(3, result[0].Power);
    }
}