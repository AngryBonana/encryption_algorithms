namespace Rijndael.Core.GaloisField;


public static class PolynomialFactorizer
{

    public static List<(int Factor, int Power)> Factorize(int p)
    {
        if (p == 0) throw new ArgumentException("Нулевой полином не раскладывается.");

        var result = new List<(int Factor, int Power)>();
        if (p == 1) return result;

        int remaining = p;
        int maxDeg = Deg(p) / 2;

        var candidates = new List<int>();
        for (int d = 1; d <= maxDeg; d++)
        {
            int start = 1 << d;
            int end = 1 << (d + 1);
            for (int q = start; q < end; q++)
            {
                if (IsIrreduciblePoly(q))
                    candidates.Add(q);
            }
        }

        foreach (var q in candidates)
        {
            int count = 0;
            while (true)
            {
                Div(remaining, q, out int rem);
                if (rem != 0) break;
                remaining = Div(remaining, q, out _);
                count++;
            }
            if (count > 0) result.Add((q, count));
        }

        if (remaining > 1)
        {
            bool merged = false;
            for (int i = 0; i < result.Count; i++)
            {
                if (result[i].Factor == remaining)
                {
                    result[i] = (remaining, result[i].Power + 1);
                    merged = true;
                    break;
                }
            }
            if (!merged) result.Add((remaining, 1));
        }

        return result;
    }

    private static int Deg(int p)
    {
        if (p == 0) return -1;
        int d = 0;
        while ((p >>= 1) != 0) d++;
        return d;
    }

    private static bool IsIrreduciblePoly(int p)
    {
        int deg = Deg(p);
        if (deg <= 1) return true;

        for (int d = 1; d <= deg / 2; d++)
        {
            int start = 1 << d;
            int end = 1 << (d + 1);
            for (int q = start; q < end; q++)
            {
                Div(p, q, out int rem);
                if (rem == 0) return false;
            }
        }
        return true;
    }

    private static int Div(int a, int b, out int rem)
    {
        int quotient = 0;
        int degB = Deg(b);
        while (a != 0 && Deg(a) >= degB)
        {
            int shift = Deg(a) - degB;
            quotient ^= 1 << shift;
            a ^= b << shift;
        }
        rem = a;
        return quotient;
    }
}