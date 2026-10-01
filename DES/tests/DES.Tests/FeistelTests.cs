using DES.Core.Abstractions;
using DES.Core.Ciphers;
using Xunit;

namespace DES.Core.Tests;

public class FeistelNetworkTests
{
    // -----------------------------------------------------------------
    // Фейковые зависимости
    // -----------------------------------------------------------------

    /// <summary>
    /// Планировщик, который возвращает ровно N копий одного и того же ключа.
    /// Если задать expectedRounds, вернёт именно столько; иначе — сколько скажут.
    /// </summary>
    private sealed class FakeKeyScheduler : IKeyScheduler
    {
        private readonly int _roundsToReturn;
        private readonly byte[] _roundKey;

        public int CallCount { get; private set; }
        public byte[]? LastKey { get; private set; }

        public FakeKeyScheduler(int roundsToReturn, byte[]? roundKey = null)
        {
            _roundsToReturn = roundsToReturn;
            _roundKey = roundKey ?? new byte[] { 0x01, 0x02, 0x03, 0x04 };
        }

        public byte[][] GenerateRoundKeys(byte[] key)
        {
            CallCount++;
            LastKey = (byte[])key.Clone();

            var result = new byte[_roundsToReturn][];
            for (int i = 0; i < _roundsToReturn; i++)
                result[i] = (byte[])_roundKey.Clone();
            return result;
        }
    }

    /// <summary>
    /// Round-функция: XOR половины блока с раундовым ключом,
    /// повторённым/усечённым до длины половины.
    /// Детерминирована и легко предсказуема.
    /// </summary>
    private sealed class XorRoundFunction : IRoundFunction
    {
        public byte[] Transform(byte[] halfBlock, byte[] roundKey)
        {
            var result = new byte[halfBlock.Length];
            for (int i = 0; i < halfBlock.Length; i++)
                result[i] = (byte)(halfBlock[i] ^ roundKey[i % roundKey.Length]);
            return result;
        }
    }

    /// <summary>
    /// Round-функция, возвращающая константу — удобно для «нулевого» влияния.
    /// </summary>
    private sealed class ConstantRoundFunction : IRoundFunction
    {
        private readonly byte[] _value;
        public ConstantRoundFunction(byte[] value) => _value = value;

        public byte[] Transform(byte[] halfBlock, byte[] roundKey) => (byte[])_value.Clone();
    }

    private static FeistelNetwork CreateCipher(
        int blockSize = 8,
        int rounds = 4,
        bool swapAfterLastRound = true,
        IRoundFunction? roundFunction = null,
        IKeyScheduler? scheduler = null)
    {
        roundFunction ??= new XorRoundFunction();
        scheduler ??= new FakeKeyScheduler(rounds);
        return new FeistelNetwork(scheduler, roundFunction, blockSize, rounds, swapAfterLastRound);
    }

    private static byte[] MakeBlock(int size, byte seed = 0)
    {
        var b = new byte[size];
        for (int i = 0; i < size; i++)
            b[i] = (byte)(seed + i);
        return b;
    }

    // -----------------------------------------------------------------
    // Конструктор: валидация
    // -----------------------------------------------------------------

    [Fact]
    public void Ctor_NullScheduler_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new FeistelNetwork(null!, new XorRoundFunction(), 8, 4));
    }

    [Fact]
    public void Ctor_NullRoundFunction_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new FeistelNetwork(new FakeKeyScheduler(4), null!, 8, 4));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(-8)]
    public void Ctor_NonPositiveBlockSize_Throws(int blockSize)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new FeistelNetwork(new FakeKeyScheduler(4), new XorRoundFunction(), blockSize, 4));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(3)]
    [InlineData(7)]
    [InlineData(9)]
    public void Ctor_OddBlockSize_Throws(int blockSize)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new FeistelNetwork(new FakeKeyScheduler(4), new XorRoundFunction(), blockSize, 4));
    }

    [Theory]
    [InlineData(2)]
    [InlineData(8)]
    [InlineData(16)]
    [InlineData(32)]
    public void Ctor_EvenBlockSize_Succeeds(int blockSize)
    {
        var cipher = new FeistelNetwork(
            new FakeKeyScheduler(4), new XorRoundFunction(), blockSize, 4);
        Assert.Equal(blockSize, cipher.BlockSizeBytes);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(-100)]
    public void Ctor_NonPositiveRounds_Throws(int rounds)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new FeistelNetwork(new FakeKeyScheduler(rounds), new XorRoundFunction(), 8, rounds));
    }

    // -----------------------------------------------------------------
    // SetKey
    // -----------------------------------------------------------------

    [Fact]
    public void SetKey_Null_Throws()
    {
        var cipher = CreateCipher();
        Assert.Throws<ArgumentNullException>(() => cipher.SetKey(null!));
    }

    [Fact]
    public void SetKey_PassesKeyToScheduler()
    {
        var scheduler = new FakeKeyScheduler(4);
        var cipher = CreateCipher(scheduler: scheduler);
        var key = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04 };

        cipher.SetKey(key);

        Assert.Equal(1, scheduler.CallCount);
        Assert.Equal(key, scheduler.LastKey);
    }

    [Fact]
    public void SetKey_ClonesKey_BeforePassingToScheduler()
    {
        var scheduler = new FakeKeyScheduler(4);
        var cipher = CreateCipher(scheduler: scheduler);
        var key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

        cipher.SetKey(key);
        key[0] = 0xFF; // портим исходный массив

        Assert.Equal(1, scheduler.LastKey![0]); // планировщик получил копию с 1, а не FF
    }

    [Fact]
    public void SetKey_SchedulerReturnsWrongRoundCount_Throws()
    {
        // Сеть настроена на 4 раунда, а планировщик возвращает 3.
        var scheduler = new FakeKeyScheduler(3);
        var cipher = new FeistelNetwork(scheduler, new XorRoundFunction(), 8, 4);

        Assert.Throws<InvalidOperationException>(() => cipher.SetKey(new byte[] { 1, 2, 3, 4 }));
    }

    [Fact]
    public void SetKey_SchedulerReturnsNull_Throws()
    {
        var cipher = new FeistelNetwork(
            new NullReturningScheduler(), new XorRoundFunction(), 8, 4);

        Assert.Throws<InvalidOperationException>(() => cipher.SetKey(new byte[] { 1, 2, 3, 4 }));
    }

    private sealed class NullReturningScheduler : IKeyScheduler
    {
        public byte[][] GenerateRoundKeys(byte[] key) => null!;
    }

    // -----------------------------------------------------------------
    // Encrypt / Decrypt: без установленного ключа
    // -----------------------------------------------------------------

    [Fact]
    public void Encrypt_WithoutKey_Throws()
    {
        var cipher = CreateCipher();
        Assert.Throws<InvalidOperationException>(() => cipher.Encrypt(MakeBlock(8)));
    }

    [Fact]
    public void Decrypt_WithoutKey_Throws()
    {
        var cipher = CreateCipher();
        Assert.Throws<InvalidOperationException>(() => cipher.Decrypt(MakeBlock(8)));
    }

    // -----------------------------------------------------------------
    // Encrypt / Decrypt: валидация аргументов
    // -----------------------------------------------------------------

    [Fact]
    public void Encrypt_Null_Throws()
    {
        var cipher = CreateCipher();
        cipher.SetKey(new byte[] { 1, 2, 3, 4 });
        Assert.Throws<ArgumentNullException>(() => cipher.Encrypt(null!));
    }

    [Fact]
    public void Decrypt_Null_Throws()
    {
        var cipher = CreateCipher();
        cipher.SetKey(new byte[] { 1, 2, 3, 4 });
        Assert.Throws<ArgumentNullException>(() => cipher.Decrypt(null!));
    }

    [Theory]
    [InlineData(7)]   // меньше блока
    [InlineData(9)]   // больше блока
    [InlineData(0)]   // пустой
    [InlineData(16)]  // в два раза больше
    public void Encrypt_WrongBlockLength_Throws(int length)
    {
        var cipher = CreateCipher(blockSize: 8);
        cipher.SetKey(new byte[] { 1, 2, 3, 4 });
        Assert.Throws<ArgumentException>(() => cipher.Encrypt(new byte[length]));
    }

    [Theory]
    [InlineData(7)]
    [InlineData(9)]
    [InlineData(0)]
    public void Decrypt_WrongBlockLength_Throws(int length)
    {
        var cipher = CreateCipher(blockSize: 8);
        cipher.SetKey(new byte[] { 1, 2, 3, 4 });
        Assert.Throws<ArgumentException>(() => cipher.Decrypt(new byte[length]));
    }

    // -----------------------------------------------------------------
    // Round-trip
    // -----------------------------------------------------------------

    [Theory]
    [InlineData(8, 1, true)]
    [InlineData(8, 1, false)]
    [InlineData(8, 4, true)]
    [InlineData(8, 4, false)]
    [InlineData(8, 16, true)]
    [InlineData(16, 16, true)]
    [InlineData(32, 32, false)]
    public void RoundTrip_Works_ForVariousConfigurations(int blockSize, int rounds, bool swap)
    {
        var cipher = CreateCipher(blockSize, rounds, swap);
        cipher.SetKey(new byte[] { 0xAA, 0xBB, 0xCC, 0xDD });

        byte[] plaintext = MakeBlock(blockSize, seed: 0x10);

        byte[] ciphertext = cipher.Encrypt(plaintext);
        byte[] decrypted = cipher.Decrypt(ciphertext);

        Assert.Equal(plaintext, decrypted);
        Assert.Equal(blockSize, ciphertext.Length);
    }

    [Fact]
    public void RoundTrip_ManyRandomBlocks()
    {
        var cipher = CreateCipher(blockSize: 16, rounds: 8);
        cipher.SetKey(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });

        var rng = new Random(12345);
        for (int i = 0; i < 200; i++)
        {
            byte[] plaintext = new byte[16];
            rng.NextBytes(plaintext);

            byte[] ciphertext = cipher.Encrypt(plaintext);
            byte[] decrypted = cipher.Decrypt(ciphertext);

            Assert.Equal(plaintext, decrypted);
        }
    }

    [Fact]
    public void RoundTrip_AllZeroBlock()
    {
        var cipher = CreateCipher(blockSize: 8, rounds: 4);
        cipher.SetKey(new byte[] { 0xAA, 0xBB, 0xCC, 0xDD });

        byte[] plaintext = new byte[8];

        byte[] decrypted = cipher.Decrypt(cipher.Encrypt(plaintext));

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void RoundTrip_AllOnesBlock()
    {
        var cipher = CreateCipher(blockSize: 8, rounds: 4);
        cipher.SetKey(new byte[] { 0xAA, 0xBB, 0xCC, 0xDD });

        byte[] plaintext = Enumerable.Repeat((byte)0xFF, 8).ToArray();

        byte[] decrypted = cipher.Decrypt(cipher.Encrypt(plaintext));

        Assert.Equal(plaintext, decrypted);
    }

    // -----------------------------------------------------------------
    // Детерминированность
    // -----------------------------------------------------------------

    [Fact]
    public void Encrypt_SameInputSameKey_ProducesSameOutput()
    {
        var cipher = CreateCipher(blockSize: 8, rounds: 8);
        cipher.SetKey(new byte[] { 1, 2, 3, 4 });

        byte[] plaintext = MakeBlock(8, seed: 0x42);

        byte[] c1 = cipher.Encrypt(plaintext);
        byte[] c2 = cipher.Encrypt(plaintext);

        Assert.Equal(c1, c2);
    }


    // -----------------------------------------------------------------
    // Конкретный случай: 2 раунда с XOR-функцией
    // -----------------------------------------------------------------

    [Fact]
    public void Encrypt_TwoRounds_WithXorRoundFunction_MatchesHandComputed()
    {
        // Блок: L0=0x01, R0=0x02
        // Round-ключ: 0x03, 0x03
        // Round function: f(x, k) = x XOR k (применяется к одному байту)
        //
        // Round 0: f(R0,k0)=0x02^0x03=0x01; newR = L0 ^ f = 0x01^0x01=0x00; (L,R)=(0x02,0x00)
        // Round 1: f(R1,k1)=0x00^0x03=0x03; newR = L1 ^ f = 0x02^0x03=0x01; (L,R)=(0x00,0x01)
        // swapAfterLastRound=true => Combine(R, L) = (0x01, 0x00)

        var scheduler = new FakeKeyScheduler(2, new byte[] { 0x03 });
        var cipher = new FeistelNetwork(
            scheduler, new XorRoundFunction(), blockSizeBytes: 2, rounds: 2, swapAfterLastRound: true);
        cipher.SetKey(new byte[] { 0xAA });

        byte[] ciphertext = cipher.Encrypt(new byte[] { 0x01, 0x02 });

        Assert.Equal(new byte[] { 0x01, 0x00 }, ciphertext);
    }

    [Fact]
    public void Encrypt_TwoRounds_NoSwap_MatchesHandComputed()
    {
        // Тот же расчёт, но без swap на последнем раунде:
        // после round 1: (L,R) = (0x00, 0x01) => Combine(L, R) = (0x00, 0x01)

        var scheduler = new FakeKeyScheduler(2, new byte[] { 0x03 });
        var cipher = new FeistelNetwork(
            scheduler, new XorRoundFunction(), blockSizeBytes: 2, rounds: 2, swapAfterLastRound: false);
        cipher.SetKey(new byte[] { 0xAA });

        byte[] ciphertext = cipher.Encrypt(new byte[] { 0x01, 0x02 });

        Assert.Equal(new byte[] { 0x00, 0x01 }, ciphertext);
    }

    // -----------------------------------------------------------------
    // Лавинный эффект: изменение одного бита во входе
    // -----------------------------------------------------------------

    [Fact]
    public void Encrypt_SingleBitFlipInPlaintext_AffectsManyOutputBits()
    {
        var cipher = CreateCipher(blockSize: 8, rounds: 8);
        cipher.SetKey(new byte[] { 0xAA, 0xBB, 0xCC, 0xDD });

        byte[] plaintext1 = MakeBlock(8, seed: 0);
        byte[] plaintext2 = (byte[])plaintext1.Clone();
        plaintext2[0] ^= 0x01; // флипаем один бит

        byte[] c1 = cipher.Encrypt(plaintext1);
        byte[] c2 = cipher.Encrypt(plaintext2);

        int differentBytes = 0;
        for (int i = 0; i < c1.Length; i++)
            if (c1[i] != c2[i])
                differentBytes++;

        // С XOR-round-функцией эффект не идеальный, но при 8 раундах
        // должно измениться хотя бы несколько байт.
        Assert.True(differentBytes >= 2,
            $"Ожидалось изменение минимум 2 байт, получили {differentBytes}.");
    }

    // -----------------------------------------------------------------
    // Свойства выхода
    // -----------------------------------------------------------------

    [Fact]
    public void Encrypt_DoesNotMutateInput()
    {
        var cipher = CreateCipher();
        cipher.SetKey(new byte[] { 1, 2, 3, 4 });

        byte[] plaintext = MakeBlock(8, seed: 0x42);
        byte[] original = (byte[])plaintext.Clone();

        cipher.Encrypt(plaintext);

        Assert.Equal(original, plaintext);
    }

    [Fact]
    public void Decrypt_DoesNotMutateInput()
    {
        var cipher = CreateCipher();
        cipher.SetKey(new byte[] { 1, 2, 3, 4 });

        byte[] ciphertext = MakeBlock(8, seed: 0x42);
        byte[] original = (byte[])ciphertext.Clone();

        cipher.Decrypt(ciphertext);

        Assert.Equal(original, ciphertext);
    }

    [Fact]
    public void Encrypt_ReturnsNewArray()
    {
        var cipher = CreateCipher();
        cipher.SetKey(new byte[] { 1, 2, 3, 4 });

        byte[] plaintext = MakeBlock(8);
        byte[] ciphertext = cipher.Encrypt(plaintext);

        Assert.NotSame(plaintext, ciphertext);
    }


    // -----------------------------------------------------------------
    // Специальный случай: 1 раунд
    // -----------------------------------------------------------------

    [Fact]
    public void Encrypt_SingleRound_MatchesHandComputed()
    {
        // L=0x01, R=0x02, k=0x03, f(x,k) = x XOR k
        // f(R,k) = 0x02^0x03 = 0x01
        // newR = L ^ f = 0x01 ^ 0x01 = 0x00
        // (L,R) = (R, newR) = (0x02, 0x00)
        // swapAfterLastRound=true => Combine(R,L) = (0x00, 0x02)

        var scheduler = new FakeKeyScheduler(1, new byte[] { 0x03 });
        var cipher = new FeistelNetwork(
            scheduler, new XorRoundFunction(), blockSizeBytes: 2, rounds: 1, swapAfterLastRound: true);
        cipher.SetKey(new byte[] { 0xAA });

        byte[] result = cipher.Encrypt(new byte[] { 0x01, 0x02 });

        Assert.Equal(new byte[] { 0x00, 0x02 }, result);
    }

    // -----------------------------------------------------------------
    // Round-trip для всех чётных размеров блока от 2 до 32
    // -----------------------------------------------------------------

    [Theory]
    [InlineData(2)]
    [InlineData(4)]
    [InlineData(6)]
    [InlineData(8)]
    [InlineData(10)]
    [InlineData(16)]
    [InlineData(24)]
    [InlineData(32)]
    public void RoundTrip_AllEvenBlockSizes(int blockSize)
    {
        var cipher = CreateCipher(blockSize, rounds: 6);
        cipher.SetKey(new byte[] { 1, 2, 3, 4 });

        byte[] plaintext = MakeBlock(blockSize, seed: 0x11);
        byte[] decrypted = cipher.Decrypt(cipher.Encrypt(plaintext));

        Assert.Equal(plaintext, decrypted);
    }

    // -----------------------------------------------------------------
    // Round-trip для разных чисел раундов
    // -----------------------------------------------------------------

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(4)]
    [InlineData(8)]
    [InlineData(16)]
    [InlineData(32)]
    public void RoundTrip_AllRoundCounts(int rounds)
    {
        var cipher = CreateCipher(blockSize: 8, rounds: rounds);
        cipher.SetKey(new byte[] { 1, 2, 3, 4 });

        byte[] plaintext = MakeBlock(8, seed: 0x22);
        byte[] decrypted = cipher.Decrypt(cipher.Encrypt(plaintext));

        Assert.Equal(plaintext, decrypted);
    }
}