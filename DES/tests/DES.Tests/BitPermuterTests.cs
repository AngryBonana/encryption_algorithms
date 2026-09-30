using DES.Core.BitPermutation;
using Xunit;

namespace CryptoLab.Core.Tests;

public class BitPermuterTests
{
    private static readonly int[] Ip =
    {
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17,  9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    };

    private static readonly int[] IpInverse =
    {
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41,  9, 49, 17, 57, 25
    };

    [Fact]
    public void Permute_Ip_MatchesClassicDesTextbookExample()
    {
        byte[] plaintext = Convert.FromHexString("0123456789ABCDEF");

        byte[] result = BitPermuter.Permute(
            plaintext, Ip, BitOrder.MsbFirst, startIndex: 1);

        Assert.Equal("CC00CCFFF0AAF0AA", Convert.ToHexString(result));
    }

    [Fact]
    public void Permute_IpThenIpInverse_ReturnsOriginalValue()
    {

        byte[] original = Convert.FromHexString("0123456789ABCDEF");

        byte[] afterIp = BitPermuter.Permute(original, Ip, BitOrder.MsbFirst, startIndex: 1);
        byte[] afterIpInverse = BitPermuter.Permute(afterIp, IpInverse, BitOrder.MsbFirst, startIndex: 1);

        Assert.Equal(original, afterIpInverse);
    }

    [Fact]
    public void Permute_SimpleReverseRule_MsbFirst_StartAt0()
    {

        byte[] input = { 0b1011_0000 };
        int[] rule = { 3, 2, 1, 0 }; // старшие 4 бита байта, в обратном порядке

        byte[] result = BitPermuter.Permute(input, rule, BitOrder.MsbFirst, startIndex: 0);

        Assert.Equal(0b1101_0000, result[0]);
    }

    [Fact]
    public void Permute_LsbFirst_ReadsBitsFromLeastSignificantEnd()
    {
        byte[] input = { 0b0000_0001 };

        int[] rule = { 0 };

        byte[] result = BitPermuter.Permute(input, rule, BitOrder.LsbFirst, startIndex: 0);

        Assert.Equal(0b1000_0000, result[0]);
    }

    [Fact]
    public void Permute_ExpandingRule_CanDuplicateBits()
    {
        // Перестановка может расширять число бит (как E-расширение в DES),
        // при этом один и тот же исходный бит может встречаться в правиле
        // несколько раз.
        byte[] input = { 0b1000_0000 }; // старший бит (позиция 0, MSB-first) = 1
        int[] rule = { 0, 0, 1 };       // берём бит 0 дважды, затем бит 1

        byte[] result = BitPermuter.Permute(input, rule, BitOrder.MsbFirst, startIndex: 0);

        // Ожидаем биты: 1, 1, 0 -> упаковано в 3 старших бита результата.
        Assert.Equal(0b1100_0000, result[0]);
    }

    [Fact]
    public void Permute_StartIndexOutOfRange_ThrowsArgumentOutOfRangeException()
    {
        byte[] input = { 0x00 };
        int[] rule = { 1 };

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            BitPermuter.Permute(input, rule, BitOrder.MsbFirst, startIndex: 2));
    }
}