using System.Numerics;
using RSA.Core.Math;
using RSA.Core.RSA;
using Xunit;

namespace RSA.Tests.Rsa;

public class RsaCryptoServiceTests
{
    [Fact]
    public void KeyGenerator_InvalidProbability_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new RsaCryptoService.KeyGeneratorService(
                RsaCryptoService.PrimalityTestType.MillerRabin, 0.4, 128));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new RsaCryptoService.KeyGeneratorService(
                RsaCryptoService.PrimalityTestType.MillerRabin, 1.0, 128));
    }

    [Theory]
    [InlineData(RsaCryptoService.PrimalityTestType.Fermat)]
    [InlineData(RsaCryptoService.PrimalityTestType.SolovayStrassen)]
    [InlineData(RsaCryptoService.PrimalityTestType.MillerRabin)]
    public void KeyGenerator_ProducesValidKeyPair(RsaCryptoService.PrimalityTestType type)
    {
        var kg = new RsaCryptoService.KeyGeneratorService(type, 0.99, 128);
        var (n, e, d) = kg.GenerateKeyPair();

        Assert.True(n > 1);
        Assert.True(e > 1);
        Assert.True(d > 1);
        Assert.Equal(BigInteger.One, NumberTheory.GcdClassic(e, d));
    }

    [Fact]
    public void EncryptDecrypt_RoundTrip_Works()
    {
        var kg = new RsaCryptoService.KeyGeneratorService(
            RsaCryptoService.PrimalityTestType.MillerRabin, 0.99, 128);
        var (n, e, d) = kg.GenerateKeyPair();

        var message = new BigInteger(123456789);
        var cipher = RsaCryptoService.Encrypt(message, e, n);
        var decrypted = RsaCryptoService.Decrypt(cipher, d, n);

        Assert.Equal(message, decrypted);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(42)]
    [InlineData(65537)]
    public void EncryptDecrypt_MultipleMessages(int m)
    {
        var kg = new RsaCryptoService.KeyGeneratorService(
            RsaCryptoService.PrimalityTestType.MillerRabin, 0.99, 128);
        var (n, e, d) = kg.GenerateKeyPair();

        var message = new BigInteger(m);
        var cipher = RsaCryptoService.Encrypt(message, e, n);
        Assert.Equal(message, RsaCryptoService.Decrypt(cipher, d, n));
    }

    [Fact]
    public void KeyGenerator_CanGenerateMultiplePairs()
    {
        var kg = new RsaCryptoService.KeyGeneratorService(
            RsaCryptoService.PrimalityTestType.MillerRabin, 0.99, 128);
        var k1 = kg.GenerateKeyPair();
        var k2 = kg.GenerateKeyPair();
        Assert.NotEqual(k1.n, k2.n);
    }
}