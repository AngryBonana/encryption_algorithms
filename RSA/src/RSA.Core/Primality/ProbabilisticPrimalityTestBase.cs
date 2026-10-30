using System;
using System.Numerics;

namespace RSA.Core.Primality;

public abstract class ProbabilisticPrimalityTestBase : IProbabilisticPrimalityTest
{
    public bool IsPrime(BigInteger value, double minProbability)
    {
        if (value <= 1) return false;
        if (value <= 3) return true;
        if (value % 2 == 0) return false;

        double probability = 0.5;
        var random = new Random();
        int iterations = 0;

        while (true)
        {
            iterations++;
            if (!RunSingleIteration(value, random))
                return false;

            probability = 1.0 - System.Math.Pow(0.5, iterations);
            if (probability >= minProbability)
                return true;
        }
    }

    protected abstract bool RunSingleIteration(BigInteger value, Random random);
}