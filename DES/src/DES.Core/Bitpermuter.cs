namespace DES.Core.BitPermutation;

public static class BitPermuter
{


    public static byte[] Permute(byte[] input, int[] permutationRule, BitOrder bitOrder, int startIndex)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(permutationRule);
 
        if (startIndex != 0 && startIndex != 1)
            throw new ArgumentOutOfRangeException(nameof(startIndex), "Start index must be 0 or 1!");
 
        int outputBitCount = permutationRule.Length;
        byte[] output = new byte[(outputBitCount + 7) / 8];
 
        for (int outputBitIndex = 0; outputBitIndex < outputBitCount; outputBitIndex++)
        {

            int sourceGlobalBitPosition = permutationRule[outputBitIndex] - startIndex;
 
            bool bitValue = GetBit(input, sourceGlobalBitPosition, bitOrder);
 
            SetBit(output, outputBitIndex, bitValue);
        }
 
        return output;
    }
 
    private static bool GetBit(byte[] data, int globalBitPosition, BitOrder bitOrder)
    {
        int byteIndex = globalBitPosition / 8;
        int bitInByte = globalBitPosition % 8;
 
        if (byteIndex < 0 || byteIndex >= data.Length)
            throw new ArgumentOutOfRangeException(nameof(globalBitPosition), $"Position of bit {globalBitPosition} is out of range. Lenght is {data.Length} bytes");
 
        int shift = GetShift(bitInByte, bitOrder);
 
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
 
    private static int GetShift(int bitInByte, BitOrder bitOrder) =>
        bitOrder switch
        {
            BitOrder.MsbFirst => 7 - bitInByte,
            BitOrder.LsbFirst => bitInByte,
            _ => throw new ArgumentOutOfRangeException(nameof(bitOrder))
        };
}
