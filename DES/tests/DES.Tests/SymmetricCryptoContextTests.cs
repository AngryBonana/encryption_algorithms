using DES.Core;
using DES.Core.Modes;
using DES.Core.Padding;
using Xunit;
using PaddingMode = DES.Core.Padding.PaddingMode;

namespace DES.Core.Tests;

public class SymmetricCryptoContextTests
{
    // 8-байтовый ключ и IV для DES.
    private static readonly byte[] Key = { 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1 };
    private static readonly byte[] Iv = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    private static readonly byte[] Delta = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };

    private static SymmetricCryptoContext Make(
        CipherMode mode,
        PaddingMode padding = PaddingMode.PKCS7,
        byte[]? iv = null,
        byte[]? delta = null)
    {
        byte[]? effectiveIv = mode == CipherMode.ECB ? null : (iv ?? Iv);

        object[] modeParams = mode == CipherMode.RandomDelta
            ? new object[] { delta ?? Delta }
            : Array.Empty<object>();

        return new SymmetricCryptoContext(
            new DesCipher(),
            (byte[])Key.Clone(),
            mode,
            padding,
            effectiveIv,
            modeParams);
    }

    // Все "настоящие" режимы паддинга. Zeros тестируется отдельно.
    public static IEnumerable<object[]> NonZerosPadding =>
        new[]
        {
            new object[] { PaddingMode.PKCS7 },
            new object[] { PaddingMode.ANSI_X923 },
            new object[] { PaddingMode.ISO10126 },
        };

    public static IEnumerable<object[]> AllModes =>
        new[]
        {
            new object[] { CipherMode.ECB },
            new object[] { CipherMode.CBC },
            new object[] { CipherMode.PCBC },
            new object[] { CipherMode.CFB },
            new object[] { CipherMode.OFB },
            new object[] { CipherMode.CTR },
            new object[] { CipherMode.RandomDelta },
        };

    public static IEnumerable<object[]> ModeAndPadding =>
        from m in new[] { CipherMode.ECB, CipherMode.CBC, CipherMode.PCBC, CipherMode.CFB,
                          CipherMode.OFB, CipherMode.CTR, CipherMode.RandomDelta }
        from p in new[] { PaddingMode.PKCS7, PaddingMode.ANSI_X923, PaddingMode.ISO10126 }
        select new object[] { m, p };

    private static byte[] MakeData(int length, byte seed = 0)
    {
        var d = new byte[length];
        for (int i = 0; i < length; i++)
            d[i] = (byte)(seed + i);
        return d;
    }

    // Граничные длины: 0, 1, blockSize-1, blockSize, blockSize+1, 10*blockSize
    private static readonly int[] BoundaryLengths = { 0, 1, 7, 8, 9, 15, 16, 17, 80, 81 };

    // =================================================================
    // Конструктор: валидация
    // =================================================================

    [Fact]
    public void Ctor_NullCipher_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new SymmetricCryptoContext(null!, Key, CipherMode.ECB, PaddingMode.PKCS7));
    }

    [Fact]
    public void Ctor_NullKey_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new SymmetricCryptoContext(new DesCipher(), null!, CipherMode.ECB, PaddingMode.PKCS7));
    }

    [Theory]
    [MemberData(nameof(AllModes))]
    public void Ctor_NonEcbWithoutIv_Throws(CipherMode mode)
    {
        if (mode == CipherMode.ECB)
            return; // ECB не требует IV

        Assert.Throws<ArgumentException>(() =>
            new SymmetricCryptoContext(
                new DesCipher(), Key, mode, PaddingMode.PKCS7, iv: null));
    }

    [Theory]
    [MemberData(nameof(AllModes))]
    public void Ctor_WrongIvLength_Throws(CipherMode mode)
    {
        if (mode == CipherMode.ECB)
            return;

        var badIv = new byte[7]; // должен быть 8
        Assert.Throws<ArgumentException>(() =>
            new SymmetricCryptoContext(
                new DesCipher(), Key, mode, PaddingMode.PKCS7, iv: badIv));
    }

    [Fact]
    public void Ctor_RandomDeltaWithoutDelta_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
            new SymmetricCryptoContext(
                new DesCipher(), Key, CipherMode.RandomDelta, PaddingMode.PKCS7, Iv));
    }

    [Fact]
    public void Ctor_RandomDeltaWithWrongDeltaLength_Throws()
    {
        var badDelta = new byte[7];
        Assert.Throws<ArgumentException>(() =>
            new SymmetricCryptoContext(
                new DesCipher(), Key, CipherMode.RandomDelta, PaddingMode.PKCS7, Iv, badDelta));
    }

    [Fact]
    public void Ctor_EcbWithIv_DoesNotThrow()
    {
        // ECB игнорирует IV, но и не запрещает его передать.
        var ctx = new SymmetricCryptoContext(
            new DesCipher(), Key, CipherMode.ECB, PaddingMode.PKCS7, Iv);
        Assert.NotNull(ctx);
    }

    // =================================================================
    // Round-trip: пакетный API
    // =================================================================

    [Theory]
    [MemberData(nameof(ModeAndPadding))]
    public void RoundTrip_Packet_AllModesAndPaddings(CipherMode mode, PaddingMode padding)
    {
        var ctx = Make(mode, padding);

        foreach (int length in BoundaryLengths)
        {
            byte[] original = MakeData(length, 0x42);

            ctx.Encrypt(original, out byte[] encrypted);
            ctx.Decrypt(encrypted, out byte[] decrypted);

            Assert.Equal(original, decrypted);
        }
    }

    [Fact]
    public void RoundTrip_Packet_RandomData()
    {
        var rng = new Random(12345);
        foreach (var mode in new[] { CipherMode.ECB, CipherMode.CBC, CipherMode.PCBC,
                                     CipherMode.CFB, CipherMode.OFB, CipherMode.CTR,
                                     CipherMode.RandomDelta })
        {
            var ctx = Make(mode);
            for (int i = 0; i < 50; i++)
            {
                int len = rng.Next(0, 200);
                var data = new byte[len];
                rng.NextBytes(data);

                ctx.Encrypt(data, out byte[] enc);
                ctx.Decrypt(enc, out byte[] dec);

                Assert.Equal(data, dec);
            }
        }
    }

    // =================================================================
    // Round-trip: потоковый API (byte[]-обёртка)
    // =================================================================

    [Theory]
    [MemberData(nameof(ModeAndPadding))]
    public void RoundTrip_Stream_AllModesAndPaddings(CipherMode mode, PaddingMode padding)
    {
        var ctx = Make(mode, padding);

        foreach (int length in BoundaryLengths)
        {
            byte[] original = MakeData(length, 0x55);

            byte[] encrypted = ctx.EncryptStream(original);
            byte[] decrypted = ctx.DecryptStream(encrypted);

            Assert.Equal(original, decrypted);
        }
    }

    [Fact]
    public void RoundTrip_Stream_LargeData()
    {
        var ctx = Make(CipherMode.CBC);
        // > 1 буфера (StreamBufferBytes = 1 МБ), чтобы проверить один переход через буфер.
        byte[] original = new byte[1 * 1024 * 1024 + 13];
        new Random(42).NextBytes(original);

        byte[] encrypted = ctx.EncryptStream(original);
        byte[] decrypted = ctx.DecryptStream(encrypted);

        Assert.Equal(original, decrypted);
    }

    // =================================================================
    // Согласованность пакетного и потокового путей
    // =================================================================

    [Theory]
    [MemberData(nameof(AllModes))]
    public void PacketAndStream_ProduceSameResult_DeterministicModes(CipherMode mode)
    {
        // ISO10126 добавляет случайные байты в паддинг — исключаем.
        // Остальные режимы детерминированы, и оба пути должны дать одно и то же.
        var ctx = Make(mode, PaddingMode.PKCS7);

        foreach (int length in new[] { 0, 1, 8, 9, 80, 81 })
        {
            byte[] data = MakeData(length, 0x11);

            ctx.Encrypt(data, out byte[] packetEnc);
            byte[] streamEnc = ctx.EncryptStream(data);

            Assert.Equal(packetEnc, streamEnc);
        }
    }

    [Theory]
    [MemberData(nameof(AllModes))]
    public void PacketAndStream_CrossDecrypt_Works(CipherMode mode)
    {
        // Шифруем пакетно — расшифровываем потоково, и наоборот.
        var ctx = Make(mode, PaddingMode.PKCS7);
        byte[] data = MakeData(100, 0x33);

        ctx.Encrypt(data, out byte[] packetEnc);
        Assert.Equal(data, ctx.DecryptStream(packetEnc));

        byte[] streamEnc = ctx.EncryptStream(data);
        ctx.Decrypt(streamEnc, out byte[] packetDec);
        Assert.Equal(data, packetDec);
    }

    // =================================================================
    // Файловые методы
    // =================================================================


    [Fact]
    public void FileRoundTrip_Sync()
    {
        // Проверим синхронные обёртки Encrypt/Decrypt(string, string).
        var ctx = Make(CipherMode.CBC);

        string tempDir = Path.Combine(Path.GetTempPath(), "DES.Tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        string inputPath = Path.Combine(tempDir, "in.bin");
        string encPath   = Path.Combine(tempDir, "enc.bin");
        string decPath   = Path.Combine(tempDir, "dec.bin");

        try
        {
            byte[] original = MakeData(1000, 0x99);
            File.WriteAllBytes(inputPath, original);

            ctx.Encrypt(inputPath, encPath);
            ctx.Decrypt(encPath, decPath);

            Assert.Equal(original, File.ReadAllBytes(decPath));
        }
        finally
        {
            try { Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }

    // =================================================================
    // Шифрование: валидация аргументов
    // =================================================================

    [Fact]
    public void Encrypt_Null_Throws()
    {
        var ctx = Make(CipherMode.CBC);
        Assert.Throws<ArgumentNullException>(() => ctx.Encrypt(null!, out _));
    }

    [Fact]
    public void Decrypt_Null_Throws()
    {
        var ctx = Make(CipherMode.CBC);
        Assert.Throws<ArgumentNullException>(() => ctx.Decrypt(null!, out _));
    }

    [Fact]
    public void DecryptStream_EmptyInput_Throws()
    {
        var ctx = Make(CipherMode.CBC);
        Assert.Throws<ArgumentException>(() => ctx.DecryptStream(Array.Empty<byte>()));
    }

    [Fact]
    public void DecryptStream_NotMultipleOfBlock_Throws()
    {
        var ctx = Make(CipherMode.CBC);
        // 9 байт — не кратно 8. Ошибку бросит либо Padder, либо проверка carry.
        Assert.ThrowsAny<ArgumentException>(() => ctx.DecryptStream(new byte[9]));
    }

    [Fact]
    public void DecryptStream_TruncatedCiphertext_Throws()
    {
        // Возьмём валидный шифротекст, обрежем на 3 байта.
        var ctx = Make(CipherMode.CBC);
        byte[] enc = ctx.EncryptStream(MakeData(20));
        byte[] truncated = enc[..^3];

        Assert.Throws<ArgumentException>(() => ctx.DecryptStream(truncated));
    }

    // =================================================================
    // Известные свойства шифрования
    // =================================================================

    [Fact]
    public void Encrypt_IsDeterministic_Packet()
    {
        var ctx = Make(CipherMode.CBC);
        byte[] data = MakeData(50);

        ctx.Encrypt(data, out byte[] e1);
        ctx.Encrypt(data, out byte[] e2);

        Assert.Equal(e1, e2);
    }

    [Fact]
    public void Encrypt_IsDeterministic_Stream()
    {
        var ctx = Make(CipherMode.CBC);
        byte[] data = MakeData(50);

        Assert.Equal(ctx.EncryptStream(data), ctx.EncryptStream(data));
    }

    [Fact]
    public void Encrypt_DifferentKeys_ProduceDifferentCiphertext()
    {
        byte[] data = MakeData(50);

        var ctx1 = new SymmetricCryptoContext(
            new DesCipher(), new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 },
            CipherMode.CBC, PaddingMode.PKCS7, Iv);
        var ctx2 = new SymmetricCryptoContext(
            new DesCipher(), new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
            CipherMode.CBC, PaddingMode.PKCS7, Iv);

        ctx1.Encrypt(data, out byte[] e1);
        ctx2.Encrypt(data, out byte[] e2);

        Assert.NotEqual(e1, e2);
    }

    [Fact]
    public void Encrypt_DifferentIv_ProduceDifferentCiphertext()
    {
        byte[] data = MakeData(50);

        var iv2 = (byte[])Iv.Clone();
        iv2[0] ^= 0xFF;

        var ctx1 = Make(CipherMode.CBC, iv: Iv);
        var ctx2 = Make(CipherMode.CBC, iv: iv2);

        ctx1.Encrypt(data, out byte[] e1);
        ctx2.Encrypt(data, out byte[] e2);

        Assert.NotEqual(e1, e2);
    }

    [Fact]
    public void Encrypt_Ecb_SameBlock_ProducesSameCiphertext()
    {
        // В ECB одинаковые блоки открытого текста шифруются одинаково.
        // Это классическая слабость ECB, и она должна наблюдаться.
        var ctx = Make(CipherMode.ECB, PaddingMode.Zeros);

        // Два одинаковых блока подряд + ещё один для паддинга.
        byte[] data = new byte[16];
        // Заполним блоки одинаково.
        for (int i = 0; i < 8; i++) data[i] = (byte)(i + 1);
        for (int i = 0; i < 8; i++) data[8 + i] = (byte)(i + 1);

        ctx.Encrypt(data, out byte[] enc);

        // Первые два блока шифротекста должны быть одинаковыми.
        Assert.Equal(enc[..8], enc[8..16]);
    }

    [Fact]
    public void Encrypt_Cbc_SameBlock_ProducesDifferentCiphertext()
    {
        // В CBC цепочка ломает эту одинаковость.
        var ctx = Make(CipherMode.CBC, PaddingMode.Zeros);

        byte[] data = new byte[16];
        for (int i = 0; i < 8; i++) data[i] = (byte)(i + 1);
        for (int i = 0; i < 8; i++) data[8 + i] = (byte)(i + 1);

        ctx.Encrypt(data, out byte[] enc);

        Assert.NotEqual(enc[..8], enc[8..16]);
    }

    [Fact]
    public void Encrypt_SingleBitFlipInPlaintext_DiffusesManyBits()
    {
        var ctx = Make(CipherMode.CBC);
        byte[] p1 = MakeData(64, 0);
        byte[] p2 = (byte[])p1.Clone();
        p2[0] ^= 0x01;

        ctx.Encrypt(p1, out byte[] c1);
        ctx.Encrypt(p2, out byte[] c2);

        int diffBytes = 0;
        for (int i = 0; i < c1.Length; i++)
            if (c1[i] != c2[i]) diffBytes++;

        Assert.True(diffBytes >= 4, $"Ожидалось ≥4 изменённых байт, получили {diffBytes}.");
    }

    // =================================================================
    // Размер выхода
    // =================================================================

    [Theory]
    [MemberData(nameof(AllModes))]
    public void Encrypt_OutputSize_IsMultipleOfBlockSize(CipherMode mode)
    {
        var ctx = Make(mode);
        foreach (int length in BoundaryLengths)
        {
            byte[] enc = ctx.EncryptStream(MakeData(length));
            Assert.Equal(0, enc.Length % 8);
            Assert.True(enc.Length >= 8);
        }
    }

    [Theory]
    [MemberData(nameof(AllModes))]
    public void Encrypt_ZeroLength_NonZerosPadding_ProducesOneBlock(CipherMode mode)
    {
        // PKCS7, ANSI_X923, ISO10126 всегда добавляют минимум один блок.
        var ctx = Make(mode, PaddingMode.PKCS7);
        byte[] enc = ctx.EncryptStream(Array.Empty<byte>());
        Assert.Equal(8, enc.Length);
    }

    // =================================================================
    // Zeros-паддинг: особенности
    // =================================================================

    [Fact]
    public void Zeros_AlignedData_ProducesSameLength()
    {
        var ctx = Make(CipherMode.ECB, PaddingMode.Zeros);
        byte[] data = MakeData(16); // кратно блоку

        byte[] enc = ctx.EncryptStream(data);

        // При Zeros и выровненных данных паддинг не добавляется.
        Assert.Equal(16, enc.Length);
    }

    [Fact]
    public void Zeros_NonAlignedData_ProducesAlignedLength()
    {
        var ctx = Make(CipherMode.ECB, PaddingMode.Zeros);
        byte[] data = MakeData(13);

        byte[] enc = ctx.EncryptStream(data);
        Assert.Equal(16, enc.Length);
    }


    // =================================================================
    // Потоковое шифрование: разные размеры буфера
    // =================================================================

    [Fact]
    public async Task EncryptAsync_SmallReads_ProducesSameAsLargeReads()
    {
        // Подаём вход по кусочкам — результат должен совпасть с одним большим чтением.
        var ctx = Make(CipherMode.CBC);
        byte[] data = MakeData(100, 0xAA);

        byte[] reference = ctx.EncryptStream(data);

        // Медленный Stream, отдающий по 3 байта за раз.
        using var slowInput = new ChunkedReadStream(data, chunkSize: 3);
        using var output = new MemoryStream();
        ctx.Encrypt(slowInput, output);

        Assert.Equal(reference, output.ToArray());
    }

    private sealed class ChunkedReadStream : Stream
    {
        private readonly byte[] _data;
        private readonly int _chunkSize;
        private int _position;

        public ChunkedReadStream(byte[] data, int chunkSize)
        {
            _data = data;
            _chunkSize = chunkSize;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => _data.Length;
        public override long Position { get => _position; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count)
        {
            int toCopy = Math.Min(Math.Min(count, _chunkSize), _data.Length - _position);
            if (toCopy <= 0) return 0;
            Array.Copy(_data, _position, buffer, offset, toCopy);
            _position += toCopy;
            return toCopy;
        }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    // =================================================================
    // Проверка состояния: повторный вызов на том же контексте
    // =================================================================

    [Fact]
    public void EncryptStream_Twice_ProducesSameResult()
    {
        // ResetStreamState должен сбрасывать состояние между вызовами.
        var ctx = Make(CipherMode.CBC);
        byte[] data = MakeData(50, 0x11);

        byte[] e1 = ctx.EncryptStream(data);
        byte[] e2 = ctx.EncryptStream(data);

        Assert.Equal(e1, e2);
    }

    [Fact]
    public void EncryptStream_AfterPacketEncrypt_ProducesSameResult()
    {
        // Пакетный путь не трогает _streamFeedback/_streamBlockIndex,
        // но ResetStreamState в начале потокового должен всё сбросить.
        var ctx = Make(CipherMode.CTR);
        byte[] data = MakeData(50, 0x22);

        ctx.Encrypt(data, out byte[] packetEnc);
        byte[] streamEnc = ctx.EncryptStream(data);

        Assert.Equal(packetEnc, streamEnc);
    }
}