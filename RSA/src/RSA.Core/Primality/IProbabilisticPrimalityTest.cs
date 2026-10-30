using System.Numerics;

namespace RSA.Core.Primality;

public interface IProbabilisticPrimalityTest
{
    bool IsPrime(BigInteger value, double minProbability);
}