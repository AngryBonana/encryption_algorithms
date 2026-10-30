using System;
using System.Numerics;
using RSA.Core.Math;
using RSA.Core.Primality;

namespace RSA.Core.RSA;

public class RsaCryptoService
{
    public enum PrimalityTestType 
    {
        Fermat,
        SolovayStrassen,
        MillerRabin
    }

    public class KeyGeneratorService
    {
        private readonly PrimalityTestType _testType;
        private readonly double _minProbability;
        private readonly int _bitLength;

        public KeyGeneratorService(PrimalityTestType testType, double minProbability, int bitLength)
        {
            if (minProbability < 0.5 || minProbability >= 1.0)
                throw new ArgumentOutOfRangeException(nameof(minProbability));
            _testType = testType;
            _minProbability = minProbability;
            _bitLength = bitLength;
        }

        public (BigInteger n, BigInteger e, BigInteger d) GenerateKeyPair()
        {
            var test = CreatePrimalityTest();
            while (true)
            {
                BigInteger p, q;
                int fermThreshold = System.Math.Max(_bitLength / 2 - 100, 8);
                var minDiff = BigInteger.One << fermThreshold;
                do
                {
                    p = GenerateProbablePrime(test);
                    q = GenerateProbablePrime(test);
                } while (p == q || BigInteger.Abs(p - q) < minDiff);

                var n = p * q;
                var phi = (p - 1) * (q - 1);
                var lambda = NumberTheory.Lcm(p - 1, q - 1);

                BigInteger e;
                do { e = RandomInRange(3, phi - 1); } while (NumberTheory.GcdClassic(e, phi) != 1);

                var (g, x, _) = NumberTheory.GcdExtended(e, lambda);
                if (g != 1) continue;
                var d = x % lambda;
                if (d < 0) d += lambda;

                if (BigInteger.Pow(d, 4) * 81 < n)
                    continue;

                return (n, e, d);
            }
        }

        private IProbabilisticPrimalityTest CreatePrimalityTest() => _testType switch
        {
            PrimalityTestType.Fermat => new FermatTest(),
            PrimalityTestType.SolovayStrassen => new SolovayStrassenTest(),
            PrimalityTestType.MillerRabin => new MillerRabinTest(),
            _ => throw new ArgumentOutOfRangeException()
        };

        private BigInteger GenerateProbablePrime(IProbabilisticPrimalityTest test)
        {
            var random = new Random();
            BigInteger candidate;
            do
            {
                candidate = RandomInRange(BigInteger.One << (_bitLength - 1), (BigInteger.One << _bitLength) - 1);
                candidate |= 1;
            } while (!test.IsPrime(candidate, _minProbability));
            return candidate;
        }

        private static BigInteger RandomInRange(BigInteger min, BigInteger max)
        {
            var random = new Random();
            var range = max - min;
            var bytes = range.ToByteArray();
            BigInteger result;
            do
            {
                random.NextBytes(bytes);
                bytes[^1] &= 0x7F;
                result = new BigInteger(bytes);
            } while (result > range);
            return min + result;
        }
    }

    public static BigInteger Encrypt(BigInteger message, BigInteger e, BigInteger n)
        => NumberTheory.ModPow(message, e, n);

    public static BigInteger Decrypt(BigInteger ciphertext, BigInteger d, BigInteger n)
        => NumberTheory.ModPow(ciphertext, d, n);
}