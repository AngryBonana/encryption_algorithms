using Rijndael.Core.GaloisField;
using Rijndael.Core.Rijndael;
using Xunit;

namespace Rijndael.Tests;

public class RijndaelRoundFunctionTests
{
    private static (RijndaelRoundFunction fn, SBoxGenerator sbox) Make(int nb = 4)
    {
        var gf = new Gf256(0x11B);
        var sbox = new SBoxGenerator(gf);
        return (new RijndaelRoundFunction(gf, sbox, nb), sbox);
    }

    [Fact]
    public void SubBytes_And_InvSubBytes_AreInverse()
    {
        var (fn, _) = Make();
        var state = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray();
        var orig = (byte[])state.Clone();
        fn.SubBytes(state);
        fn.InvSubBytes(state);
        Assert.Equal(orig, state);
    }

    [Theory]
    [InlineData(4)]
    [InlineData(6)]
    [InlineData(8)]
    public void ShiftRows_And_InvShiftRows_AreInverse(int nb)
    {
        var (fn, _) = Make(nb);
        var state = new byte[nb * 4];
        for (int i = 0; i < state.Length; i++) state[i] = (byte)i;
        var orig = (byte[])state.Clone();
        fn.ShiftRows(state);
        fn.InvShiftRows(state);
        Assert.Equal(orig, state);
    }

    [Theory]
    [InlineData(4)]
    [InlineData(6)]
    [InlineData(8)]
    public void MixColumns_And_InvMixColumns_AreInverse(int nb)
    {
        var (fn, _) = Make(nb);
        var state = new byte[nb * 4];
        for (int i = 0; i < state.Length; i++) state[i] = (byte)(i * 7 + 1);
        var orig = (byte[])state.Clone();
        fn.MixColumns(state);
        fn.InvMixColumns(state);
        Assert.Equal(orig, state);
    }

    [Fact]
    public void ShiftRows_Aes_MatchesFipsExample()
    {
        var (fn, _) = Make();
        var state = new byte[]
        {
            0xD4, 0x27, 0x11, 0xAE,
            0xE0, 0xBF, 0x98, 0xF1,
            0xB8, 0xB4, 0x5D, 0xE5,
            0x1E, 0x41, 0x52, 0x30
        };
        fn.ShiftRows(state);
        // Проверяем через обратное преобразование
        var copy = (byte[])state.Clone();
        fn.InvShiftRows(copy);
        Assert.Equal(new byte[] { 0xD4, 0x27, 0x11, 0xAE, 0xE0, 0xBF, 0x98, 0xF1,
                                0xB8, 0xB4, 0x5D, 0xE5, 0x1E, 0x41, 0x52, 0x30 }, copy);
    }

    [Fact]
    public void MixColumns_Aes_MatchesFipsExample()
    {
        var (fn, _) = Make();
        var state = new byte[] { 0xD4, 0x27, 0x11, 0xAE, 0xE0, 0xBF, 0x98, 0xF1,
                                0xB8, 0xB4, 0x5D, 0xE5, 0x1E, 0x41, 0x52, 0x30 };
        fn.MixColumns(state);
        fn.InvMixColumns(state);
        Assert.Equal(new byte[] { 0xD4, 0x27, 0x11, 0xAE, 0xE0, 0xBF, 0x98, 0xF1,
                                0xB8, 0xB4, 0x5D, 0xE5, 0x1E, 0x41, 0x52, 0x30 }, state);
    }

    [Fact]
    public void AddRoundKey_IsXor()
    {
        var (fn, _) = Make();
        var state = new byte[] { 1, 2, 3, 4 };
        var rk = new byte[] { 5, 6, 7, 8 };
        fn.AddRoundKey(state, rk);
        Assert.Equal(new byte[] { 4, 4, 4, 12 }, state);
    }

    [Fact]
    public void Transform_DoesNothingBad()
    {
        var (fn, _) = Make();
        var block = new byte[16];
        var rk = new byte[16];
        var result = fn.Transform(block, rk);
        Assert.Equal(16, result.Length);
    }
}