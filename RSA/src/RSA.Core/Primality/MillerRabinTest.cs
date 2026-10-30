using System.Numerics;
using RSA.Core.Math;

namespace RSA.Core.Primality;

public class MillerRabinTest : ProbabilisticPrimalityTestBase
{
    protected override bool RunSingleIteration(BigInteger value, Random random)
    {
        BigInteger d = value - 1;
        int s = 0;
        while (d % 2 == 0) { d /= 2; s++; }

        var a = RandomInRange(2, value - 2, random);
        BigInteger x = NumberTheory.ModPow(a, d, value);
        if (x == 1 || x == value - 1) return true;
        for (int r = 1; r < s; r++)
        {
            x = (x * x) % value;
            if (x == value - 1) return true;
            if (x == 1) return false;
        }
        return false;
    }

    private static BigInteger RandomInRange(BigInteger min, BigInteger max, Random random)
    {
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