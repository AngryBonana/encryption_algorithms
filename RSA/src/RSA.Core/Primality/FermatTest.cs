using System.Numerics;
using RSA.Core.Math;

namespace RSA.Core.Primality;

public class FermatTest : ProbabilisticPrimalityTestBase
{
    protected override bool RunSingleIteration(BigInteger value, Random random)
    {
        var a = RandomInRange(2, value - 2, random);
        return NumberTheory.ModPow(a, value - 1, value) == 1;
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