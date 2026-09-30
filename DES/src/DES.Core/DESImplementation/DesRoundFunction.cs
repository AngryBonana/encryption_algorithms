using DES.Core.Abstractions;
using DES.Core.BitPermutation;
using DES.Core.Tables;

namespace DES.Core;


public sealed class DesRoundFunction : IRoundFunction
{
    public byte[] Transform(byte[] block, byte[] roundKey)
    {
        ArgumentNullException.ThrowIfNull(block);
        ArgumentNullException.ThrowIfNull(roundKey);

        if (block.Length != 4)
            throw new ArgumentException("Раундовая функция DES принимает 4 байта (32 бита).", nameof(block));
        if (roundKey.Length != 6)
            throw new ArgumentException("Раундовый ключ DES должен быть 6 байт (48 бит).", nameof(roundKey));

        byte[] expanded = BitPermuter.Permute(block, DesTables.E, BitOrder.MsbFirst, 1);

        byte[] xored = new byte[6];
        for (int i = 0; i < 6; i++)
            xored[i] = (byte)(expanded[i] ^ roundKey[i]);

        byte[] substituted = ApplySBoxes(xored);

        return BitPermuter.Permute(substituted, DesTables.P, BitOrder.MsbFirst, 1);
    }

    private static byte[] ApplySBoxes(byte[] input)
    {
        byte[] output = new byte[4];

        for (int i = 0; i < 8; i++)
        {
            int b0 = GetBit(input, i * 6 + 0) ? 1 : 0;
            int b1 = GetBit(input, i * 6 + 1) ? 1 : 0;
            int b2 = GetBit(input, i * 6 + 2) ? 1 : 0;
            int b3 = GetBit(input, i * 6 + 3) ? 1 : 0;
            int b4 = GetBit(input, i * 6 + 4) ? 1 : 0;
            int b5 = GetBit(input, i * 6 + 5) ? 1 : 0;

            int row = (b0 << 1) | b5;
            int col = (b1 << 3) | (b2 << 2) | (b3 << 1) | b4;

            int value = DesTables.SBoxes[i][row, col];

            SetBit(output, i * 4 + 0, (value & 0b1000) != 0);
            SetBit(output, i * 4 + 1, (value & 0b0100) != 0);
            SetBit(output, i * 4 + 2, (value & 0b0010) != 0);
            SetBit(output, i * 4 + 3, (value & 0b0001) != 0);
        }

        return output;
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
}