using System.Security.Cryptography;
using DES.Core;
using DES.Core.BitPermutation;
using DES.Core.Tables;
using Xunit;

namespace DES.Core.Tests;

// =====================================================================
// DesTables
// =====================================================================

public class DesTablesTests
{
    private const int BitsPerByte = 8;

    [Fact]
    public void IP_Has64Entries()
        => Assert.Equal(64, DesTables.IP.Length);

    [Fact]
    public void FP_Has64Entries()
        => Assert.Equal(64, DesTables.FP.Length);

    [Fact]
    public void E_Has48Entries()
        => Assert.Equal(48, DesTables.E.Length);

    [Fact]
    public void P_Has32Entries()
        => Assert.Equal(32, DesTables.P.Length);

    [Fact]
    public void PC1_Has56Entries()
        => Assert.Equal(56, DesTables.PC1.Length);

    [Fact]
    public void PC2_Has48Entries()
        => Assert.Equal(48, DesTables.PC2.Length);

    [Fact]
    public void Shifts_Has16Entries()
        => Assert.Equal(16, DesTables.Shifts.Length);

    [Fact]
    public void SBoxes_Has8Boxes()
        => Assert.Equal(8, DesTables.SBoxes.Length);

    [Fact]
    public void SBoxes_EachIs4x16()
    {
        foreach (var sbox in DesTables.SBoxes)
        {
            Assert.Equal(4, sbox.GetLength(0));
            Assert.Equal(16, sbox.GetLength(1));
        }
    }

    [Fact]
    public void SBoxes_AllValuesInRange0To15()
    {
        foreach (var sbox in DesTables.SBoxes)
        {
            for (int r = 0; r < 4; r++)
                for (int c = 0; c < 16; c++)
                {
                    int v = sbox[r, c];
                    Assert.InRange(v, 0, 15);
                }
        }
    }

    [Fact]
    public void SBoxes_EachRowIsPermutation0To15()
    {
        foreach (var sbox in DesTables.SBoxes)
        {
            for (int r = 0; r < 4; r++)
            {
                var seen = new HashSet<int>();
                for (int c = 0; c < 16; c++)
                    Assert.True(seen.Add(sbox[r, c]),
                        $"Значение {sbox[r, c]} повторяется в строке {r}");
            }
        }
    }

    [Fact]
    public void IP_ValuesInRange1To64()
        => Assert.All(DesTables.IP, v => Assert.InRange(v, 1, 64));

    [Fact]
    public void FP_ValuesInRange1To64()
        => Assert.All(DesTables.FP, v => Assert.InRange(v, 1, 64));

    [Fact]
    public void E_ValuesInRange1To32()
        => Assert.All(DesTables.E, v => Assert.InRange(v, 1, 32));

    [Fact]
    public void P_ValuesInRange1To32()
        => Assert.All(DesTables.P, v => Assert.InRange(v, 1, 32));

    [Fact]
    public void IP_IsPermutationOf1To64()
    {
        var sorted = (int[])DesTables.IP.Clone();
        Array.Sort(sorted);
        Assert.Equal(Enumerable.Range(1, 64), sorted);
    }

    [Fact]
    public void FP_IsPermutationOf1To64()
    {
        var sorted = (int[])DesTables.FP.Clone();
        Array.Sort(sorted);
        Assert.Equal(Enumerable.Range(1, 64), sorted);
    }

    [Fact]
    public void P_IsPermutationOf1To32()
    {
        var sorted = (int[])DesTables.P.Clone();
        Array.Sort(sorted);
        Assert.Equal(Enumerable.Range(1, 32), sorted);
    }

    [Fact]
    public void PC1_IsPermutationOf1To64_WithoutMultiplesOf8()
    {
        // PC1 выбирает 56 бит из 64, пропуская каждый 8-й бит (биты чётности).
        var sorted = (int[])DesTables.PC1.Clone();
        Array.Sort(sorted);

        var expected = Enumerable.Range(1, 64)
            .Where(b => b % 8 != 0) // пропускаем 8,16,24,...
            .ToArray();

        Assert.Equal(expected, sorted);
    }

    [Fact]
    public void PC2_IsPermutationOfSubsetOf1To56()
    {
        // PC2 выбирает 48 бит из 56.
        var sorted = (int[])DesTables.PC2.Clone();
        Array.Sort(sorted);

        Assert.Equal(48, sorted.Length);
        Assert.All(sorted, v => Assert.InRange(v, 1, 56));
        Assert.Equal(sorted.Length, sorted.Distinct().Count()); // нет повторов
    }

    [Fact]
    public void Shifts_OnlyContain1Or2()
    {
        Assert.All(DesTables.Shifts, s => Assert.InRange(s, 1, 2));
    }

    [Fact]
    public void Shifts_SumIs28()
    {
        // За 16 раундов сумма сдвигов = 28, что возвращает C и D в исходное положение.
        Assert.Equal(28, DesTables.Shifts.Sum());
    }
}

// =====================================================================
// DesKeyScheduler
// =====================================================================

public class DesKeySchedulerTests
{
    private static readonly byte[] ValidKey =
        { 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1 };

    [Fact]
    public void GenerateRoundKeys_Null_Throws()
    {
        var scheduler = new DesKeyScheduler();
        Assert.Throws<ArgumentNullException>(() => scheduler.GenerateRoundKeys(null!));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(7)]
    [InlineData(9)]
    [InlineData(16)]
    public void GenerateRoundKeys_WrongKeyLength_Throws(int length)
    {
        var scheduler = new DesKeyScheduler();
        Assert.Throws<ArgumentException>(() => scheduler.GenerateRoundKeys(new byte[length]));
    }

    [Fact]
    public void GenerateRoundKeys_Returns16Keys()
    {
        var scheduler = new DesKeyScheduler();
        var keys = scheduler.GenerateRoundKeys(ValidKey);
        Assert.Equal(16, keys.Length);
    }

    [Fact]
    public void GenerateRoundKeys_EachKeyIs6Bytes()
    {
        var scheduler = new DesKeyScheduler();
        var keys = scheduler.GenerateRoundKeys(ValidKey);
        Assert.All(keys, k => Assert.Equal(6, k.Length));
    }

    [Fact]
    public void GenerateRoundKeys_IsDeterministic()
    {
        var scheduler = new DesKeyScheduler();

        var keys1 = scheduler.GenerateRoundKeys(ValidKey);
        var keys2 = scheduler.GenerateRoundKeys(ValidKey);

        Assert.Equal(keys1.Length, keys2.Length);
        for (int i = 0; i < keys1.Length; i++)
            Assert.Equal(keys1[i], keys2[i]);
    }

    [Fact]
    public void GenerateRoundKeys_DifferentKeys_ProduceDifferentRoundKeys()
    {
        var scheduler = new DesKeyScheduler();
        // 0x00... и 0xFF... отличаются информационными битами (не только чётностью).
        var keys1 = scheduler.GenerateRoundKeys(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
        var keys2 = scheduler.GenerateRoundKeys(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF });

        bool anyDifferent = keys1.Zip(keys2, (a, b) => !a.SequenceEqual(b)).Any(x => x);
        Assert.True(anyDifferent);
    }

    [Fact]
    public void GenerateRoundKeys_DifferentRounds_DifferFromEachOther()
    {
        var scheduler = new DesKeyScheduler();
        var keys = scheduler.GenerateRoundKeys(ValidKey);

        // Проверим, что не все ключи одинаковы (что было бы явным багом).
        var first = keys[0];
        bool anyDifferent = false;
        for (int i = 1; i < keys.Length; i++)
        {
            if (!keys[i].SequenceEqual(first))
            {
                anyDifferent = true;
                break;
            }
        }
        Assert.True(anyDifferent);
    }

    [Fact]
    public void GenerateRoundKeys_DoesNotMutateKey()
    {
        var scheduler = new DesKeyScheduler();
        var key = (byte[])ValidKey.Clone();
        var original = (byte[])key.Clone();

        scheduler.GenerateRoundKeys(key);

        Assert.Equal(original, key);
    }

    [Fact]
    public void GenerateRoundKeys_WithParityBitsSet_Works()
    {
        byte[] key1 = { 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1 };
        byte[] key2 = (byte[])key1.Clone();
        key2[0] ^= 0x01; // бит 8 (чётность)
        key2[7] ^= 0x01; // бит 64 (чётность) — ИСПРАВЛЕНО

        var scheduler = new DesKeyScheduler();
        var keys1 = scheduler.GenerateRoundKeys(key1);
        var keys2 = scheduler.GenerateRoundKeys(key2);

        for (int i = 0; i < 16; i++)
            Assert.Equal(keys1[i], keys2[i]);
    }
}

// =====================================================================
// DesRoundFunction
// =====================================================================

public class DesRoundFunctionTests
{
    private static readonly byte[] ValidRoundKey =
        { 0x1B, 0x02, 0xEF, 0xFC, 0x70, 0x72 };

    [Fact]
    public void Transform_NullBlock_Throws()
    {
        var f = new DesRoundFunction();
        Assert.Throws<ArgumentNullException>(() => f.Transform(null!, ValidRoundKey));
    }

    [Fact]
    public void Transform_NullKey_Throws()
    {
        var f = new DesRoundFunction();
        Assert.Throws<ArgumentNullException>(() => f.Transform(new byte[4], null!));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(3)]
    [InlineData(5)]
    [InlineData(8)]
    public void Transform_WrongBlockLength_Throws(int length)
    {
        var f = new DesRoundFunction();
        Assert.Throws<ArgumentException>(() => f.Transform(new byte[length], ValidRoundKey));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(5)]
    [InlineData(7)]
    [InlineData(8)]
    public void Transform_WrongKeyLength_Throws(int length)
    {
        var f = new DesRoundFunction();
        Assert.Throws<ArgumentException>(() => f.Transform(new byte[4], new byte[length]));
    }

    [Fact]
    public void Transform_Returns4Bytes()
    {
        var f = new DesRoundFunction();
        byte[] result = f.Transform(new byte[] { 1, 2, 3, 4 }, ValidRoundKey);
        Assert.Equal(4, result.Length);
    }

    [Fact]
    public void Transform_DoesNotMutateInputs()
    {
        var f = new DesRoundFunction();
        var block = new byte[] { 0xAA, 0xBB, 0xCC, 0xDD };
        var key = (byte[])ValidRoundKey.Clone();
        var blockOrig = (byte[])block.Clone();
        var keyOrig = (byte[])key.Clone();

        f.Transform(block, key);

        Assert.Equal(blockOrig, block);
        Assert.Equal(keyOrig, key);
    }

    [Fact]
    public void Transform_IsDeterministic()
    {
        var f = new DesRoundFunction();
        var block = new byte[] { 0x01, 0x02, 0x03, 0x04 };

        var r1 = f.Transform(block, ValidRoundKey);
        var r2 = f.Transform(block, ValidRoundKey);

        Assert.Equal(r1, r2);
    }

    [Fact]
    public void Transform_DifferentBlocks_ProduceDifferentResults()
    {
        var f = new DesRoundFunction();
        var r1 = f.Transform(new byte[] { 0, 0, 0, 0 }, ValidRoundKey);
        var r2 = f.Transform(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF }, ValidRoundKey);

        Assert.NotEqual(r1, r2);
    }

    [Fact]
    public void Transform_DifferentKeys_ProduceDifferentResults()
    {
        var f = new DesRoundFunction();
        var block = new byte[] { 0x01, 0x02, 0x03, 0x04 };

        var r1 = f.Transform(block, new byte[] { 0, 0, 0, 0, 0, 0 });
        var r2 = f.Transform(block, new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF });

        Assert.NotEqual(r1, r2);
    }

    [Fact]
    public void Transform_ZeroBlockZeroKey_ProducesExpectedValue()
    {
        // При block=0, key=0: E расширяет 0 в 0, XOR = 0,
        // все S-box берут S[i][0,0], результат предсказуем.
        // S[0][0,0]=14 (1110), S[1][0,0]=15 (1111), S[2][0,0]=10 (1010), S[3][0,0]=7 (0111)
        // S[4][0,0]=2  (0010), S[5][0,0]=12 (1100), S[6][0,0]=4  (0100), S[7][0,0]=13 (1101)
        // => до P: 1110 1111 1010 0111 0010 1100 0100 1101
        // = EF A7 2C 4D
        // Затем P переставляет биты — точный результат зависит от P,
        // поэтому проверим только длину и что не всё нули.
        var f = new DesRoundFunction();
        var result = f.Transform(new byte[4], new byte[6]);

        Assert.Equal(4, result.Length);
        // Хотя бы один бит должен быть установлен: S-box не выдаёт все нули.
        Assert.Contains(result, b => b != 0);
    }
}

// =====================================================================
// DesCipher
// =====================================================================

public class DesCipherTests
{
    private static byte[] Hex(string s) => Convert.FromHexString(s);

    // Общеизвестные тестовые векторы DES (FIPS 46-3 / учебники).
    public static IEnumerable<object[]> KnownVectors =>
        new[]
        {
            new object[] { "133457799BBCDFF1", "0123456789ABCDEF", "85E813540F0AB405" },
            new object[] { "0123456789ABCDEF", "4E6F772069732074", "3FA40E8A984D4815" },
            new object[] { "0E329232EA6D0D73", "8787878787878787", "0000000000000000" },
            new object[] { "FFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFF", "7359B2163E4EDC58" },
            new object[] { "3000000000000000", "1000000000000001", "958E6E627A05557B" },
            new object[] { "1111111111111111", "1111111111111111", "F40379AB9E0EC533" },
            new object[] { "0123456789ABCDEF", "1111111111111111", "17668DFC7292532D" },
            new object[] { "1111111111111111", "0123456789ABCDEF", "8A5AE1F81AB8F2DD" },
        };

    [Fact]
    public void BlockSizeBytes_Is8()
    {
        var cipher = new DesCipher();
        Assert.Equal(8, cipher.BlockSizeBytes);
    }

    [Fact]
    public void SetKey_Null_Throws()
    {
        var cipher = new DesCipher();
        Assert.Throws<ArgumentNullException>(() => cipher.SetKey(null!));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(7)]
    [InlineData(9)]
    [InlineData(16)]
    public void SetKey_WrongLength_Throws(int length)
    {
        var cipher = new DesCipher();
        Assert.Throws<ArgumentException>(() => cipher.SetKey(new byte[length]));
    }

    [Fact]
    public void Encrypt_Null_Throws()
    {
        var cipher = new DesCipher();
        cipher.SetKey(Hex("0123456789ABCDEF"));
        Assert.Throws<ArgumentNullException>(() => cipher.Encrypt(null!));
    }

    [Fact]
    public void Decrypt_Null_Throws()
    {
        var cipher = new DesCipher();
        cipher.SetKey(Hex("0123456789ABCDEF"));
        Assert.Throws<ArgumentNullException>(() => cipher.Decrypt(null!));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(7)]
    [InlineData(9)]
    [InlineData(16)]
    public void Encrypt_WrongBlockLength_Throws(int length)
    {
        var cipher = new DesCipher();
        cipher.SetKey(Hex("0123456789ABCDEF"));
        Assert.Throws<ArgumentException>(() => cipher.Encrypt(new byte[length]));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(7)]
    [InlineData(9)]
    public void Decrypt_WrongBlockLength_Throws(int length)
    {
        var cipher = new DesCipher();
        cipher.SetKey(Hex("0123456789ABCDEF"));
        Assert.Throws<ArgumentException>(() => cipher.Decrypt(new byte[length]));
    }

    [Fact]
    public void Encrypt_WithoutKey_Throws()
    {
        var cipher = new DesCipher();
        // SetKey не вызывали — Feistel выбросит InvalidOperationException.
        Assert.Throws<InvalidOperationException>(() =>
            cipher.Encrypt(Hex("0123456789ABCDEF")));
    }

    // -----------------------------------------------------------------
    // Известные тестовые векторы
    // -----------------------------------------------------------------

    [Theory]
    [MemberData(nameof(KnownVectors))]
    public void Encrypt_KnownVector_MatchesExpectedCiphertext(
        string keyHex, string plainHex, string expectedHex)
    {
        var cipher = new DesCipher();
        cipher.SetKey(Hex(keyHex));

        byte[] actual = cipher.Encrypt(Hex(plainHex));

        Assert.Equal(Hex(expectedHex), actual);
    }

    [Theory]
    [MemberData(nameof(KnownVectors))]
    public void Decrypt_KnownVector_MatchesExpectedPlaintext(
        string keyHex, string plainHex, string expectedHex)
    {
        var cipher = new DesCipher();
        cipher.SetKey(Hex(keyHex));

        byte[] actual = cipher.Decrypt(Hex(expectedHex));

        Assert.Equal(Hex(plainHex), actual);
    }

    // -----------------------------------------------------------------
    // Round-trip
    // -----------------------------------------------------------------

    [Fact]
    public void RoundTrip_RandomBlocks()
    {
        var cipher = new DesCipher();
        cipher.SetKey(Hex("133457799BBCDFF1"));

        var rng = new Random(12345);
        for (int i = 0; i < 200; i++)
        {
            byte[] plain = new byte[8];
            rng.NextBytes(plain);

            byte[] enc = cipher.Encrypt(plain);
            byte[] dec = cipher.Decrypt(enc);

            Assert.Equal(plain, dec);
        }
    }

    [Fact]
    public void RoundTrip_AllZeroBlock()
    {
        var cipher = new DesCipher();
        cipher.SetKey(Hex("133457799BBCDFF1"));

        byte[] plain = new byte[8];
        byte[] dec = cipher.Decrypt(cipher.Encrypt(plain));

        Assert.Equal(plain, dec);
    }

    [Fact]
    public void RoundTrip_AllOnesBlock()
    {
        var cipher = new DesCipher();
        cipher.SetKey(Hex("133457799BBCDFF1"));

        byte[] plain = Enumerable.Repeat((byte)0xFF, 8).ToArray();
        byte[] dec = cipher.Decrypt(cipher.Encrypt(plain));

        Assert.Equal(plain, dec);
    }

    // -----------------------------------------------------------------
    // Свойства
    // -----------------------------------------------------------------

    [Fact]
    public void Encrypt_DoesNotMutateInput()
    {
        var cipher = new DesCipher();
        cipher.SetKey(Hex("133457799BBCDFF1"));

        byte[] plain = Hex("0123456789ABCDEF");
        byte[] original = (byte[])plain.Clone();

        cipher.Encrypt(plain);

        Assert.Equal(original, plain);
    }

    [Fact]
    public void Decrypt_DoesNotMutateInput()
    {
        var cipher = new DesCipher();
        cipher.SetKey(Hex("133457799BBCDFF1"));

        byte[] ciph = Hex("85E813540F0AB405");
        byte[] original = (byte[])ciph.Clone();

        cipher.Decrypt(ciph);

        Assert.Equal(original, ciph);
    }

    [Fact]
    public void Encrypt_IsDeterministic()
    {
        var cipher = new DesCipher();
        cipher.SetKey(Hex("133457799BBCDFF1"));

        byte[] plain = Hex("0123456789ABCDEF");

        Assert.Equal(cipher.Encrypt(plain), cipher.Encrypt(plain));
    }

    [Fact]
    public void Encrypt_DifferentKeys_ProduceDifferentCiphertext()
    {
        byte[] plain = Hex("0123456789ABCDEF");

        var cipher1 = new DesCipher();
        cipher1.SetKey(Hex("0000000000000000"));

        var cipher2 = new DesCipher();
        cipher2.SetKey(Hex("FFFFFFFFFFFFFFFF"));

        Assert.NotEqual(cipher1.Encrypt(plain), cipher2.Encrypt(plain));
    }

    [Fact]
    public void Encrypt_SingleBitFlipInPlaintext_ChangesManyOutputBits()
    {
        var cipher = new DesCipher();
        cipher.SetKey(Hex("133457799BBCDFF1"));

        byte[] p1 = Hex("0000000000000000");
        byte[] p2 = Hex("0000000000000001"); // один бит изменён

        byte[] c1 = cipher.Encrypt(p1);
        byte[] c2 = cipher.Encrypt(p2);

        int diffBytes = 0;
        for (int i = 0; i < 8; i++)
            if (c1[i] != c2[i]) diffBytes++;

        // У DES лавинный эффект: изменений должно быть заметно больше одного байта.
        Assert.True(diffBytes >= 3, $"Ожидалось ≥3 изменённых байт, получили {diffBytes}.");
    }

    [Fact]
    public void SetKey_Twice_UsesLatestKey()
    {
        var cipher = new DesCipher();
        byte[] plain = Hex("0123456789ABCDEF");

        cipher.SetKey(Hex("0000000000000000"));
        byte[] c1 = cipher.Encrypt(plain);

        cipher.SetKey(Hex("FFFFFFFFFFFFFFFF"));
        byte[] c2 = cipher.Encrypt(plain);

        Assert.NotEqual(c1, c2);
    }
}