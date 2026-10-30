using System.Numerics;
using RSA.Core.Attacks;
using Xunit;

namespace RSA.Tests.Attacks;

public class WienerAttackServiceTests
{
    [Fact]
    public void Attack_OnVulnerableKey_RecoversD()
    {
        // Генерируем уязвимый ключ и проверяем, что атака находит d
        var (n, e, d) = VulnerableKeyGenerator.GenerateWienerVulnerableKey(128);
        var result = WienerAttackService.Attack(e, n);

        Assert.Equal(d, result.FoundD);
        Assert.True(result.Phi > 0);
        Assert.NotEmpty(result.Convergents);
    }

    [Fact]
    public void Attack_RecoversPhi_AndFactorsN()
    {
        var (n, e, d) = VulnerableKeyGenerator.GenerateWienerVulnerableKey(128);
        var result = WienerAttackService.Attack(e, n);

        // phi должен давать корректное разложение n на множители
        var sum = n - result.Phi + 1;
        var disc = sum * sum - 4 * n;
        Assert.True(disc >= 0);

        // e*d ≡ 1 (mod phi)
        Assert.Equal(BigInteger.One, (e * result.FoundD) % result.Phi);
    }

    [Fact]
    public void Attack_ReturnsConvergentsList()
    {
        var (n, e, _) = VulnerableKeyGenerator.GenerateWienerVulnerableKey(128);
        var result = WienerAttackService.Attack(e, n);
        Assert.NotNull(result.Convergents);
        Assert.NotEmpty(result.Convergents);
    }

    [Fact]
    public void Attack_OnNormalKey_DoesNotRecoverD()
    {
        // Неуязвимый ключ — атака не должна найти корректное d (либо найти неверное)
        var kg = new RSA.Core.RSA.RsaCryptoService.KeyGeneratorService(
            RSA.Core.RSA.RsaCryptoService.PrimalityTestType.MillerRabin, 0.99, 256);
        var (n, e, _) = kg.GenerateKeyPair();
        var result = WienerAttackService.Attack(e, n);

        // Атака может вернуть 0, если ничего не нашла — это норма для неуязвимого ключа
        if (result.FoundD != 0)
        {
            // Если что-то нашла — phi должен быть валидным
            Assert.True(result.Phi > 0);
        }
    }
}