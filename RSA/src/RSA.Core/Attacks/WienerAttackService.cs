using System.Collections.Generic;
using System.Numerics;
using RSA.Core.Math;

namespace RSA.Core.Attacks;

public class WienerAttackService
{
    public record AttackResult(
        BigInteger FoundD,
        BigInteger Phi,
        List<(BigInteger numerator, BigInteger denominator)> Convergents);

    public static AttackResult Attack(BigInteger e, BigInteger n)
    {
        var convergents = ContinuedFractions.GetConvergents(e, n);
        foreach (var (k, d) in convergents)
        {
            if (k == 0) continue;

            if ((e * d - 1) % k != 0) continue;
            
            var phi = (e * d - 1) / k;
            var sum = n - phi + 1;
            var discriminant = sum * sum - 4 * n;

            if (discriminant < 0) continue;
            var sqrt = IntegerSqrt(discriminant);

            if (sqrt * sqrt != discriminant) continue;

            var p = (sum + sqrt) / 2;
            var q = (sum - sqrt) / 2;

            if (p * q == n)
                return new AttackResult(d, phi, convergents);
        }
        return new AttackResult(0, 0, convergents);
    }

    private static BigInteger IntegerSqrt(BigInteger n)
    {
        if (n < 0) return -1;
        if (n == 0) return 0;

        var x = n;
        var y = (x + 1) / 2;
        
        while (y < x) 
        {
            x = y;
            y = (x + n / x) / 2;
        }
        return x;
    }
}