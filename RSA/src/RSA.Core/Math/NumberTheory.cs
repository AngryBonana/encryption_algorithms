using System;
using System.Collections.Generic;
using System.Numerics;

namespace RSA.Core.Math;

public static class NumberTheory
{
    public static int LegendreSymbol(BigInteger a, BigInteger p)
    {
        a %= p;
        if (a < 0) a += p;
        if (a == 0) return 0;
        var result = BigInteger.ModPow(a, (p - 1) / 2, p);
        return result == 1 ? 1 : -1;
    }

    public static int JacobiSymbol(BigInteger a, BigInteger n)
    {
        if (n <= 0 || n % 2 == 0) throw new ArgumentException("n must be odd positive");
        a %= n;
        int result = 1;
        while (a != 0)
        {
            while (a % 2 == 0)
            {
                a /= 2;
                var nMod8 = (int)(n % 8);
                if (nMod8 == 3 || nMod8 == 5) result = -result;
            }
            (a, n) = (n, a);
            if (a % 4 == 3 && n % 4 == 3) result = -result;
            a %= n;
        }
        return n == 1 ? result : 0;
    }

    public static BigInteger GcdClassic(BigInteger a, BigInteger b)
    {
        a = BigInteger.Abs(a); b = BigInteger.Abs(b);
        while (b != 0) (a, b) = (b, a % b);
        return a;
    }

    public static (BigInteger g, BigInteger x, BigInteger y) GcdExtended(BigInteger a, BigInteger b)
    {
        BigInteger oldR = BigInteger.Abs(a), r = BigInteger.Abs(b);
        BigInteger oldS = 1, s = 0;
        BigInteger oldT = 0, t = 1;
        while (r != 0)
        {
            var q = oldR / r;
            (oldR, r) = (r, oldR - q * r);
            (oldS, s) = (s, oldS - q * s);
            (oldT, t) = (t, oldT - q * t);
        }
        if (a < 0) oldS = -oldS;
        if (b < 0) oldT = -oldT;
        return (oldR, oldS, oldT);
    }

    public static BigInteger GcdBinary(BigInteger a, BigInteger b)
    {
        a = BigInteger.Abs(a); b = BigInteger.Abs(b);
        if (a == 0) return b;
        if (b == 0) return a;
        int shift = 0;
        while (((a | b) & 1) == 0)
        {
            a >>= 1;
            b >>= 1;
            shift++;
        }

        while ((a & 1) == 0) a >>= 1;
        do
        {
            while ((b & 1) == 0) b >>= 1;
            if (a > b) (a, b) = (b, a);
            b -= a;
        } while (b != 0);
        return a << shift;
    }

    public static BigInteger ModPow(BigInteger baseValue, BigInteger exponent, BigInteger modulus)
    {
        if (modulus == 1) return 0;
        BigInteger result = 1;
        baseValue %= modulus;
        while (exponent > 0)
        {
            if ((exponent & 1) == 1) result = (result * baseValue) % modulus;
            baseValue = (baseValue * baseValue) % modulus;
            exponent >>= 1;
        }
        return result;
    }

    public static BigInteger EulerPhiByDefinition(BigInteger n)
    {
        BigInteger count = 0;
        for (BigInteger k = 1; k <= n; k++)
            if (GcdClassic(k, n) == 1) count++;
        return count;
    }

    public static BigInteger EulerPhiByFactorization(BigInteger n)
    {
        var factors = GetPrimeFactors(n);
        BigInteger result = n;
        foreach (var p in factors.Keys)
            result = result / p * (p - 1);
        return result;
    }

    public static double EulerPhiByDft(BigInteger n)
    {
        double sum = 0;
        for (BigInteger k = 1; k <= n; k++)
        {
            double angle = 2.0 * System.Math.PI * (double)k / (double)n;
            sum += (double)GcdClassic(k, n) * System.Math.Cos(angle);
        }
        return sum;
    }

    public static BigInteger CarmichaelLambda(BigInteger n)
    {
        if (n == 1) return 1;
        var factors = GetPrimeFactors(n);
        BigInteger lambda = 1;
        foreach (var (p, exp) in factors)
        {
            BigInteger primePower = BigInteger.Pow(p, exp);
            BigInteger phiPrimePower = primePower / p * (p - 1);
            BigInteger component;
            if (p == 2 && exp >= 3)
                component = phiPrimePower / 2;
            else
                component = phiPrimePower;
            lambda = Lcm(lambda, component);
        }
        return lambda;
    }

    public static BigInteger Lcm(BigInteger a, BigInteger b) => a / GcdClassic(a, b) * b;

    public static Dictionary<BigInteger, int> GetPrimeFactors(BigInteger n)
    {
        var factors = new Dictionary<BigInteger, int>();
        if (n <= 1) return factors;
        for (BigInteger p = 2; p * p <= n; p += (p == 2 ? 1 : 2))
        {
            while (n % p == 0)
            {
                factors[p] = factors.GetValueOrDefault(p) + 1;
                n /= p;
            }
        }
        if (n > 1) factors[n] = 1;
        return factors;
    }
}