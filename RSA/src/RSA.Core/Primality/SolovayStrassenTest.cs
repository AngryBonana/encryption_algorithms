using System.Numerics;
using RSA.Core.Math;

namespace RSA.Core.Primality;

public class SolovayStrassenTest : ProbabilisticPrimalityTestBase
{
    protected override bool RunSingleIteration(BigInteger value, Random random)
    {
        var a = RandomInRange(2, value - 2, random);
        var jacobi = NumberTheory.JacobiSymbol(a, value);
        var modPow = NumberTheory.ModPow(a, (value - 1) / 2, value);

        BigInteger modPowSigned = modPow == value - 1 ? -1 : modPow;
        return modPowSigned == jacobi;
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