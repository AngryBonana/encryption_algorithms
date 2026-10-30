using System;
using System.Numerics;
using RSA.Core.Math;
using RSA.Core.Primality;

namespace RSA.Core.Attacks;

public static class VulnerableKeyGenerator
{
    public static (BigInteger n, BigInteger e, BigInteger d) GenerateWienerVulnerableKey(int bits = 128)
    {
        var mr = new MillerRabinTest();

        while (true)
        {
            var p = GeneratePrime(bits, mr);
            var q = GeneratePrime(bits, mr);
            var n = p * q;
            var phi = (p - 1) * (q - 1);

            var d = new BigInteger(3);
            while (NumberTheory.GcdClassic(d, phi) != 1)
                d += 2;

            if (BigInteger.Pow(d, 4) * 81 >= n)
                continue;

            var (g, x, _) = NumberTheory.GcdExtended(d, phi);
            if (g != 1)
                continue;

            var e = x % phi;
            if (e < 0) e += phi;
            if (e == 1)
                continue;

            return (n, e, d);
        }
    }

    private static BigInteger GeneratePrime(int bits, IProbabilisticPrimalityTest test)
    {
        var random = new Random();
        while (true)
        {
            var bytes = new byte[bits / 8];
            random.NextBytes(bytes);
            bytes[^1] &= 0x7F;
            var candidate = new BigInteger(bytes);
            candidate |= 1;
            if (candidate < 3) candidate = 3;

            if (test.IsPrime(candidate, 0.99))
                return candidate;
        }
    }
}