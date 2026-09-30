using DES.Core.Abstractions;
using DES.Core.BitPermutation;
using DES.Core.Tables;

namespace DES.Core;

public sealed class DesKeyScheduler : IKeyScheduler
{
    private const int Rounds = 16;

    public byte[][] GenerateRoundKeys(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length != 8)
            throw new ArgumentException("Ключ DES должен быть длиной 8 байт (64 бита).", nameof(key));

        byte[] permuted = BitPermuter.Permute(key, DesTables.PC1, BitOrder.MsbFirst, 1);

        bool[] c = new bool[28];
        bool[] d = new bool[28];
        for (int i = 0; i < 28; i++)
            c[i] = GetBit(permuted, i);
        for (int i = 0; i < 28; i++)
            d[i] = GetBit(permuted, 28 + i);

        byte[][] roundKeys = new byte[Rounds][];
        for (int round = 0; round < Rounds; round++)
        {
            int shift = DesTables.Shifts[round];
            c = LeftRotate(c, shift);
            d = LeftRotate(d, shift);

            byte[] cd = new byte[7];
            for (int i = 0; i < 28; i++)
                SetBit(cd, i, c[i]);
            for (int i = 0; i < 28; i++)
                SetBit(cd, 28 + i, d[i]);

            roundKeys[round] = BitPermuter.Permute(cd, DesTables.PC2, BitOrder.MsbFirst, 1);
        }

        return roundKeys;
    }


    private static bool GetBit(byte[] data, int globalBitPosition)
    {
        int byteIndex = globalBitPosition / 8;
        int bitInByte = globalBitPosition % 8;
        int shift = 7 - bitInByte;
        return ((data[byteIndex] >> shift) & 1) == 1;
    }

    private static void SetBit(byte[] data, int globalBitPosition, bool value)
    {
        int byteIndex = globalBitPosition / 8;
        int bitInByte = globalBitPosition % 8;
        int shift = 7 - bitInByte;
        if (value)
            data[byteIndex] |= (byte)(1 << shift);
        else
            data[byteIndex] &= (byte)~(1 << shift);
    }

    private static bool[] LeftRotate(bool[] bits, int shift)
    {
        int n = bits.Length;
        bool[] result = new bool[n];
        for (int i = 0; i < n; i++)
            result[i] = bits[(i + shift) % n];
        return result;
    }
}