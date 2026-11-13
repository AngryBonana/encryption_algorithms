using System.Numerics;

namespace Rijndael.Core.GaloisField;

public sealed class Gf256
{
    public byte Modulus { get; }

    public Gf256(byte modulus)
    {
        if (!IsIrreducible(modulus))
            throw new ArgumentException(
                $"Полином 0x{0x100 | modulus:X} не является неприводимым над GF(2).");

        Modulus = modulus;
    }

    public byte Add(byte a, byte b) => (byte)(a ^ b);

    public byte Multiply(byte a, byte b)
    {
        byte result = 0;
        for (int i = 0; i < 8; i++)
        {
            if ((b & 1) != 0)
                result ^= a;

            bool highBit = (a & 0x80) != 0;
            a <<= 1;
            if (highBit)
                a ^= Modulus;

            b >>= 1;
        }
        return result;
    }

    public byte Inverse(byte a)
    {
        if (a == 0)
            throw new InvalidOperationException("Обратный элемент для 0 в GF(2^8) не существует.");

        int r0 = FullPoly(Modulus), r1 = a;
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

        return (byte)s0;
    }

    public static bool IsIrreducible(byte modulus)
    {
        int p = FullPoly(modulus);

        if ((p & 1) == 0) return false;

        if (BitOperations.PopCount((uint)p) % 2 == 0) return false;

        for (int d = 2; d <= 4; d++)
        {
            for (int divisor = 1 << d; divisor < 1 << (d + 1); divisor++)
            {
                PolyDiv(p, divisor, out int rem);
                if (rem == 0) return false;
            }
        }
        return true;
    }

    public static List<byte> FindAllIrreducibleDegree8()
    {
        var result = new List<byte>();
        for (int m = 0; m <= 0xFF; m++)
        {
            if (IsIrreducible((byte)m))
                result.Add((byte)m);
        }
        return result;
    }

    private static int FullPoly(byte modulus) => 0x100 | modulus;

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
        while (a != 0 && Deg(a) >= degB)
        {
            int shift = Deg(a) - degB;
            quotient ^= 1 << shift;
            a ^= b << shift;
        }
        remainder = a;
        return quotient;
    }

    private static int Deg(int p) => p == 0 ? -1 : 31 - BitOperations.LeadingZeroCount((uint)p);
}