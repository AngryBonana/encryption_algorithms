namespace Rijndael.Core.GaloisField;

public sealed class Gf256
{
    public int Modulus { get; }

    public Gf256(int modulus)
    {
        if ((modulus & 0x100) == 0 || modulus > 0x1FF)
            throw new ArgumentException("Модуль должен быть полиномом степени 8 (0x100..0x1FF).");

        if (!IsIrreducible(modulus))
            throw new ArgumentException($"Полином 0x{modulus:X} не является неприводимым над GF(2).");

        Modulus = modulus;
    }

    public byte Add(byte a, byte b) => (byte)(a ^ b);

    public byte Multiply(byte a, byte b)
    {
        int result = 0;
        int aa = a;
        int bb = b;
        for (int i = 0; i < 8; i++)
        {
            if ((bb & 1) != 0)
                result ^= aa;

            bool highBit = (aa & 0x80) != 0;
            aa = (aa << 1) & 0xFF;
            if (highBit)
                aa ^= (Modulus & 0xFF);

            bb >>= 1;
        }
        return (byte)(result & 0xFF);
    }

    public byte Inverse(byte a)
    {
        if (a == 0)
            throw new InvalidOperationException("Обратный элемент для 0 в GF(2^8) не существует.");

        int r0 = Modulus, r1 = a;
        int s0 = 0, s1 = 1;

        while (r1 != 0)
        {
            int q = PolyDiv(r0, r1, out int r);
            int s2 = s0 ^ PolyMul(s1, q);
            r0 = r1; r1 = r;
            s0 = s1; s1 = s2;
        }

        if (r0 != 1)
            throw new InvalidOperationException("Элемент не имеет обратного (модуль не неприводим).");

        return (byte)(s0 & 0xFF);
    }

    private static int PolyMul(int a, int b)
    {
        int result = 0;
        while (b != 0)
        {
            if ((b & 1) != 0) result ^= a;
            a <<= 1;
            b >>= 1;
        }
        return result;
    }

    private static int PolyDiv(int a, int b, out int remainder)
    {
        if (b == 0) throw new DivideByZeroException();
        int quotient = 0;
        int degB = Deg(b);
        while (Deg(a) >= degB && a != 0)
        {
            int shift = Deg(a) - degB;
            quotient ^= 1 << shift;
            a ^= b << shift;
        }
        remainder = a;
        return quotient;
    }

    private static int Deg(int p)
    {
        if (p == 0) return -1;
        int d = 0;
        while ((p >>= 1) != 0) d++;
        return d;
    }
    private static byte PolyEval(int p, byte x)
    {
        int result = 0;
        int deg = Deg(p);
        for (int i = deg; i >= 0; i--)
        {
            result = PolyMul(result, x);
            int coeff = (p >> i) & 1;
            result ^= coeff;
        }
        return (byte)result;
    }

    public static bool IsIrreducible(int p)
    {
        if (Deg(p) != 8) return false;

        int parity = 0;
        int t = p;
        while (t != 0) { parity ^= (t & 1); t >>= 1; }
        if ((p & 1) == 0) return false;
        if (parity == 0) return false;

        for (int d = 2; d <= 4; d++)
        {
            int start = 1 << d;
            int end = 1 << (d + 1);
            for (int divisor = start; divisor < end; divisor++)
            {
                PolyDiv(p, divisor, out int rem);
                if (rem == 0) return false;
            }
        }
        return true;
    }

    public static List<int> FindAllIrreducibleDegree8()
    {
        var result = new List<int>();
        for (int p = 0x100; p <= 0x1FF; p++)
        {
            if (IsIrreducible(p))
                result.Add(p);
        }
        return result;
    }
}