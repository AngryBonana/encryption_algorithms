using System.Numerics;
using RSA.Core.Attacks;
using RSA.Core.Math;
using Xunit;

namespace RSA.Tests.Attacks;

public class VulnerableKeyGeneratorTests
{
    [Fact]
    public void Generate_ReturnsValidKeyTriple()
    {
        var (n, e, d) = VulnerableKeyGenerator.GenerateWienerVulnerableKey(128);
        Assert.True(n > 1);
        Assert.True(e > 1);
        Assert.True(d > 1);
    }

    [Fact]
    public void Generate_SatisfiesWienerCondition()
    {
        var (n, _, d) = VulnerableKeyGenerator.GenerateWienerVulnerableKey(128);
        // Условие Винера: d^4 < n / 81 (эквивалентно d < n^(1/4)/3)
        Assert.True(BigInteger.Pow(d, 4) * 81 < n);
    }

    [Fact]
    public void Generate_EDCongruentOneModPhi()
    {
        var (n, e, d) = VulnerableKeyGenerator.GenerateWienerVulnerableKey(128);
        var result = WienerAttackService.Attack(e, n);
        Assert.Equal(BigInteger.One, (e * d) % result.Phi);
    }

    [Fact]
    public void Generate_CanProduceDifferentKeys()
    {
        var k1 = VulnerableKeyGenerator.GenerateWienerVulnerableKey(128);
        var k2 = VulnerableKeyGenerator.GenerateWienerVulnerableKey(128);
        Assert.NotEqual(k1.n, k2.n);
    }

    [Fact]
    public void Generate_KeyIsAttackableByWiener()
    {
        var (n, e, d) = VulnerableKeyGenerator.GenerateWienerVulnerableKey(128);
        var result = WienerAttackService.Attack(e, n);
        Assert.Equal(d, result.FoundD);
    }
}