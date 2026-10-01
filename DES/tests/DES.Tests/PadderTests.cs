using CryptographicException = System.Security.Cryptography.CryptographicException;
using DES.Core.Padding;
using Xunit;

namespace DES.Core.Tests;

public class PadderTests
{
    // Удобный перебор всех "настоящих" режимов паддинга.
    // Zeros тестируется отдельно, т.к. ведёт себя иначе.
    public static IEnumerable<object[]> AllPaddingModes =>
        new[]
        {
            new object[] { PaddingMode.PKCS7 },
            new object[] { PaddingMode.ANSI_X923 },
            new object[] { PaddingMode.ISO10126 },
        };

    // Размеры блоков: DES (8), AES (16), "странный" (5), минимальный (1), максимальный (255).
    public static IEnumerable<object[]> BlockSizes =>
        new[]
        {
            new object[] { 1 },
            new object[] { 5 },
            new object[] { 8 },
            new object[] { 16 },
            new object[] { 255 },
        };

    private static byte[] MakeData(int length, byte fill = 0xAB)
    {
        var data = new byte[length];
        Array.Fill(data, fill);
        return data;
    }

    // -----------------------------------------------------------------
    // Pad: базовые проверки
    // -----------------------------------------------------------------

    public static IEnumerable<object[]> ModeAndBlockSize =>
        from mode in new[] { PaddingMode.PKCS7, PaddingMode.ANSI_X923, PaddingMode.ISO10126 }
        from blockSize in new[] { 1, 5, 8, 16, 255 }
        select new object[] { mode, blockSize };

    [Theory]
    [MemberData(nameof(ModeAndBlockSize))]
    public void Pad_AlwaysAddsAtLeastOneByte_NonZerosModes(PaddingMode mode, int blockSize)
    {
        foreach (int length in new[] { 0, 1, blockSize - 1, blockSize, blockSize + 1, 2 * blockSize })
        {
            byte[] data = MakeData(length);
            byte[] padded = Padder.Pad(data, blockSize, mode);

            Assert.True(padded.Length > length);
            Assert.Equal(0, padded.Length % blockSize);
        }
    }

    [Theory]
    [MemberData(nameof(AllPaddingModes))]
    public void Pad_PreservesOriginalData_AtTheBeginning(PaddingMode mode)
    {
        int blockSize = 8;
        byte[] data = MakeData(13, 0x42);

        byte[] padded = Padder.Pad(data, blockSize, mode);

        Assert.Equal(data, padded[..data.Length]);
    }

    [Fact]
    public void Pad_NullData_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            Padder.Pad(null!, 8, PaddingMode.PKCS7));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(256)]
    [InlineData(int.MaxValue)]
    public void Pad_InvalidBlockSize_Throws(int blockSize)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            Padder.Pad(MakeData(10), blockSize, PaddingMode.PKCS7));
    }

    [Fact]
    public void Pad_InvalidMode_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            Padder.Pad(MakeData(10), 8, (PaddingMode)999));
    }

    // -----------------------------------------------------------------
    // Pad: конкретные значения байтов паддинга
    // -----------------------------------------------------------------

    [Fact]
    public void Pad_PKCS7_FillsAllPaddingBytesWithPadLength()
    {
        int blockSize = 8;
        byte[] data = MakeData(5); // remainder = 5, padLength = 3

        byte[] padded = Padder.Pad(data, blockSize, PaddingMode.PKCS7);

        Assert.Equal(8, padded.Length);
        Assert.Equal(3, padded[5]);
        Assert.Equal(3, padded[6]);
        Assert.Equal(3, padded[7]);
    }

    [Fact]
    public void Pad_PKCS7_FullBlockPad_WhenAlreadyAligned()
    {
        int blockSize = 8;
        byte[] data = MakeData(8);

        byte[] padded = Padder.Pad(data, blockSize, PaddingMode.PKCS7);

        Assert.Equal(16, padded.Length);
        for (int i = 8; i < 16; i++)
            Assert.Equal(8, padded[i]);
    }

    [Fact]
    public void Pad_ANSI_X923_LastByteIsPadLength_RestAreZeros()
    {
        int blockSize = 8;
        byte[] data = MakeData(5, 0xFF); // padLength = 3

        byte[] padded = Padder.Pad(data, blockSize, PaddingMode.ANSI_X923);

        Assert.Equal(8, padded.Length);
        Assert.Equal(0, padded[5]);
        Assert.Equal(0, padded[6]);
        Assert.Equal(3, padded[7]);
    }

    [Fact]
    public void Pad_ANSI_X923_FullBlockPad()
    {
        int blockSize = 8;
        byte[] data = MakeData(8);

        byte[] padded = Padder.Pad(data, blockSize, PaddingMode.ANSI_X923);

        Assert.Equal(16, padded.Length);
        for (int i = 8; i < 15; i++)
            Assert.Equal(0, padded[i]);
        Assert.Equal(8, padded[15]);
    }

    [Fact]
    public void Pad_ISO10126_LastByteIsPadLength_RestRandom()
    {
        int blockSize = 16;
        byte[] data = MakeData(10); // padLength = 6

        byte[] padded = Padder.Pad(data, blockSize, PaddingMode.ISO10126);

        Assert.Equal(16, padded.Length);
        Assert.Equal(6, padded[15]);
        // Предыдущие 5 байт — случайные, конкретное значение не проверяем,
        // но они не обязаны совпадать с data.
    }

    [Fact]
    public void Pad_ISO10126_PadLength1_LastByteIs1()
    {
        int blockSize = 8;
        byte[] data = MakeData(7); // padLength = 1

        byte[] padded = Padder.Pad(data, blockSize, PaddingMode.ISO10126);

        Assert.Equal(8, padded.Length);
        Assert.Equal(1, padded[7]);
    }

    [Fact]
    public void Pad_Zeros_AppendsZeros()
    {
        int blockSize = 8;
        byte[] data = MakeData(5, 0xCC);

        byte[] padded = Padder.Pad(data, blockSize, PaddingMode.Zeros);

        Assert.Equal(8, padded.Length);
        Assert.Equal(0, padded[5]);
        Assert.Equal(0, padded[6]);
        Assert.Equal(0, padded[7]);
    }

    [Fact]
    public void Pad_Zeros_AlignedData_ReturnsClone_NoExtraBlock()
    {
        int blockSize = 8;
        byte[] data = MakeData(8, 0xCC);

        byte[] padded = Padder.Pad(data, blockSize, PaddingMode.Zeros);

        Assert.Equal(8, padded.Length);
        Assert.Equal(data, padded);
        Assert.NotSame(data, padded); // это клон
    }

    [Fact]
    public void Pad_Zeros_EmptyData_ReturnsEmpty()
    {
        byte[] padded = Padder.Pad(Array.Empty<byte>(), 8, PaddingMode.Zeros);
        Assert.Empty(padded);
    }

    // -----------------------------------------------------------------
    // Unpad: базовые проверки
    // -----------------------------------------------------------------

    [Theory]
    [MemberData(nameof(ModeAndBlockSize))]
    public void RoundTrip_ArbitraryLengths(PaddingMode mode, int blockSize)
    {
        foreach (int length in new[] { 0, 1, blockSize - 1, blockSize, blockSize + 1, 5 * blockSize + 3 })
        {
            byte[] original = MakeData(length, 0x5A);
            byte[] padded = Padder.Pad(original, blockSize, mode);
            byte[] restored = Padder.Unpad(padded, mode);
            Assert.Equal(original, restored);
        }
    }

    [Fact]
    public void Unpad_NullData_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            Padder.Unpad(null!, PaddingMode.PKCS7));
    }

    [Fact]
    public void Unpad_EmptyData_NonZerosMode_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            Padder.Unpad(Array.Empty<byte>(), PaddingMode.PKCS7));
    }

    [Fact]
    public void Unpad_InvalidMode_Throws()
    {
        // Для Zeros не бросает; берём другой режим, чтобы проверить default-ветку.
        // Но default сработает только если padLength валиден; сделаем валидный.
        byte[] data = { 0xAA, 0x01 };
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            Padder.Unpad(data, (PaddingMode)999));
    }

    // -----------------------------------------------------------------
    // Unpad: конкретные сценарии
    // -----------------------------------------------------------------

    [Fact]
    public void Unpad_PKCS7_ValidPadding_Works()
    {
        // 5 байт данных + 3 байта паддинга (значение 3)
        byte[] padded = { 1, 2, 3, 4, 5, 3, 3, 3 };

        byte[] unpadded = Padder.Unpad(padded, PaddingMode.PKCS7);

        Assert.Equal(new byte[] { 1, 2, 3, 4, 5 }, unpadded);
    }

    [Fact]
    public void Unpad_PKCS7_InvalidPadding_Throws()
    {
        // Последний байт 3, но предпоследний 4 — несоответствие.
        byte[] padded = { 1, 2, 3, 4, 5, 4, 3, 3 };

        Assert.Throws<CryptographicException>(() =>
            Padder.Unpad(padded, PaddingMode.PKCS7));
    }

    [Fact]
    public void Unpad_PKCS7_PadLengthZero_Throws()
    {
        byte[] padded = { 1, 2, 3, 4, 5, 6, 7, 0 };

        Assert.Throws<Exception>(() =>
            Padder.Unpad(padded, PaddingMode.PKCS7));
    }

    [Fact]
    public void Unpad_PKCS7_PadLengthTooLarge_Throws()
    {
        // padLength = 100, больше длины массива
        byte[] padded = { 1, 2, 3, 100 };

        Assert.Throws<Exception>(() =>
            Padder.Unpad(padded, PaddingMode.PKCS7));
    }

    [Fact]
    public void Unpad_ANSI_X923_ValidPadding_Works()
    {
        // 5 байт данных + 3 байта паддинга: 0, 0, 3
        byte[] padded = { 1, 2, 3, 4, 5, 0, 0, 3 };

        byte[] unpadded = Padder.Unpad(padded, PaddingMode.ANSI_X923);

        Assert.Equal(new byte[] { 1, 2, 3, 4, 5 }, unpadded);
    }

    [Fact]
    public void Unpad_ANSI_X923_InvalidPadding_Throws()
    {
        // В паддинге должен быть 0, а стоит 0xFF
        byte[] padded = { 1, 2, 3, 4, 5, 0xFF, 0, 3 };

        Assert.Throws<CryptographicException>(() =>
            Padder.Unpad(padded, PaddingMode.ANSI_X923));
    }

    [Fact]
    public void Unpad_ISO10126_IgnoresPaddingContent()
    {
        // ISO10126 не проверяет содержимое (кроме последнего байта).
        byte[] padded = { 1, 2, 3, 4, 5, 0xAA, 0xBB, 3 };

        byte[] unpadded = Padder.Unpad(padded, PaddingMode.ISO10126);

        Assert.Equal(new byte[] { 1, 2, 3, 4, 5 }, unpadded);
    }

    [Fact]
    public void Unpad_Zeros_TrimsAllTrailingZeros()
    {
        byte[] padded = { 1, 2, 3, 0, 0, 0, 0, 0 };

        byte[] unpadded = Padder.Unpad(padded, PaddingMode.Zeros);

        Assert.Equal(new byte[] { 1, 2, 3 }, unpadded);
    }

    [Fact]
    public void Unpad_Zeros_NoTrailingZeros_ReturnsSame()
    {
        byte[] padded = { 1, 2, 3, 4 };

        byte[] unpadded = Padder.Unpad(padded, PaddingMode.Zeros);

        Assert.Equal(padded, unpadded);
    }

    [Fact]
    public void Unpad_Zeros_AllZeros_ReturnsEmpty()
    {
        byte[] padded = { 0, 0, 0, 0 };

        byte[] unpadded = Padder.Unpad(padded, PaddingMode.Zeros);

        Assert.Empty(unpadded);
    }

    [Fact]
    public void Unpad_Zeros_EmptyData_ReturnsEmpty()
    {
        byte[] unpadded = Padder.Unpad(Array.Empty<byte>(), PaddingMode.Zeros);
        Assert.Empty(unpadded);
    }

    // -----------------------------------------------------------------
    // Unpad: один блок (для потокового режима)
    // -----------------------------------------------------------------

    [Theory]
    [MemberData(nameof(ModeAndBlockSize))]
    public void Unpad_SingleBlock_Works_ForStreamingUseCase(PaddingMode mode, int blockSize)
    {
        byte[] data = MakeData(blockSize - 1, 0x77);
        byte[] padded = Padder.Pad(data, blockSize, mode);
        Assert.Equal(blockSize, padded.Length);
        byte[] restored = Padder.Unpad(padded, mode);
        Assert.Equal(data, restored);
    }

    // -----------------------------------------------------------------
    // Round-trip: рандомные данные, много прогонов
    // -----------------------------------------------------------------

    [Theory]
    [MemberData(nameof(AllPaddingModes))]
    public void RoundTrip_RandomData_ManyIterations(PaddingMode mode)
    {
        var rng = new Random(12345);
        int blockSize = 16;

        for (int iter = 0; iter < 100; iter++)
        {
            int length = rng.Next(0, 200);
            byte[] data = new byte[length];
            rng.NextBytes(data);

            byte[] padded = Padder.Pad(data, blockSize, mode);
            byte[] restored = Padder.Unpad(padded, mode);

            Assert.Equal(data, restored);
        }
    }

    // -----------------------------------------------------------------
    // ISO10126: два вызова Pad дают разный результат (случайность)
    // -----------------------------------------------------------------

    [Fact]
    public void Pad_ISO10126_TwoCalls_ProduceDifferentPadding()
    {
        byte[] data = MakeData(5);

        byte[] first = Padder.Pad(data, 16, PaddingMode.ISO10126);
        byte[] second = Padder.Pad(data, 16, PaddingMode.ISO10126);

        // Совпадает только последний байт (длина паддинга), остальное — рандом.
        // С вероятностью 1/256^10 они совпадут — но для теста это приемлемо.
        Assert.NotEqual(first, second);
    }

    // -----------------------------------------------------------------
    // Zeros: известная особенность — теряет хвостовые нули
    // -----------------------------------------------------------------

    [Fact]
    public void Zeros_LosesTrailingZeros_KnownLimitation()
    {
        // Это документирующий тест: Zeros-паддинг не отличает
        // настоящие нули в конце данных от паддинга.
        byte[] original = { 1, 2, 3, 0, 0 }; // заканчивается нулями

        byte[] padded = Padder.Pad(original, 8, PaddingMode.Zeros);
        byte[] restored = Padder.Unpad(padded, PaddingMode.Zeros);

        Assert.NotEqual(original, restored); // нули потеряны
        Assert.Equal(new byte[] { 1, 2, 3 }, restored);
    }
}