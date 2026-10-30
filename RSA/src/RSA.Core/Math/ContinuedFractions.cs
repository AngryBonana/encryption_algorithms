using System.Collections.Generic;
using System.Numerics;

namespace RSA.Core.Math;

public static class ContinuedFractions
{
    public static List<(BigInteger numerator, BigInteger denominator)> GetConvergents(BigInteger numerator, BigInteger denominator)
    {
        var quotients = new List<BigInteger>();
        BigInteger a = numerator, b = denominator;
        while (b != 0)
        {
            quotients.Add(a / b);
            (a, b) = (b, a % b);
        }

        var convergents = new List<(BigInteger, BigInteger)>();
        BigInteger hPrev2 = 0, hPrev1 = 1;
        BigInteger kPrev2 = 1, kPrev1 = 0;
        
        foreach (var q in quotients)
        {
            var h = q * hPrev1 + hPrev2;
            var k = q * kPrev1 + kPrev2;
            convergents.Add((h, k));
            (hPrev2, hPrev1) = (hPrev1, h);
            (kPrev2, kPrev1) = (kPrev1, k);
        }
        return convergents;
    }
}