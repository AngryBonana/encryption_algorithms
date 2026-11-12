using Rijndael.Core.Abstractions;
using Rijndael.Core.GaloisField;

namespace Rijndael.Core.Rijndael;

public sealed class RijndaelRoundFunction : IRoundFunction
{
    private readonly Gf256 _gf;
    private readonly SBoxGenerator _sbox;
    private readonly int _nb;

    public RijndaelRoundFunction(Gf256 gf, SBoxGenerator sbox, int nb = 4)
    {
        _gf = gf;
        _sbox = sbox;
        _nb = nb;
    }

    public byte[] Transform(byte[] block, byte[] roundKey)
    {
        var s = (byte[])block.Clone();
        AddRoundKey(s, roundKey);
        SubBytes(s);
        ShiftRows(s);
        MixColumns(s);
        return s;
    }

    public byte[] InverseTransform(byte[] block, byte[] roundKey)
    {
        var s = (byte[])block.Clone();
        InvMixColumns(s);
        InvShiftRows(s);
        InvSubBytes(s);
        AddRoundKey(s, roundKey);
        return s;
    }

    public void AddRoundKey(byte[] state, byte[] roundKey)
    {
        for (int i = 0; i < state.Length; i++)
            state[i] ^= roundKey[i];
    }

    public void SubBytes(byte[] state)
    {
        for (int i = 0; i < state.Length; i++)
            state[i] = _sbox.SBox[state[i]];
    }

    public void InvSubBytes(byte[] state)
    {
        for (int i = 0; i < state.Length; i++)
            state[i] = _sbox.InvSBox[state[i]];
    }

    public void ShiftRows(byte[] state)
    {
        var tmp = new byte[state.Length];
        for (int r = 0; r < 4; r++)
        {
            for (int c = 0; c < _nb; c++)
            {
                int srcCol = (c + r) % _nb;
                tmp[r + 4 * c] = state[r + 4 * srcCol];
            }
        }
        Array.Copy(tmp, state, state.Length);
    }

    public void InvShiftRows(byte[] state)
    {
        var tmp = new byte[state.Length];
        for (int r = 0; r < 4; r++)
        {
            for (int c = 0; c < _nb; c++)
            {
                int srcCol = (c - r + _nb * 4) % _nb;
                tmp[r + 4 * c] = state[r + 4 * srcCol];
            }
        }
        Array.Copy(tmp, state, state.Length);
    }

    public void MixColumns(byte[] state)
    {
        for (int c = 0; c < _nb; c++)
        {
            byte a0 = state[0 + 4 * c];
            byte a1 = state[1 + 4 * c];
            byte a2 = state[2 + 4 * c];
            byte a3 = state[3 + 4 * c];

            state[0 + 4 * c] = (byte)(_gf.Multiply(a0, 2) ^ _gf.Multiply(a1, 3) ^ a2 ^ a3);
            state[1 + 4 * c] = (byte)(a0 ^ _gf.Multiply(a1, 2) ^ _gf.Multiply(a2, 3) ^ a3);
            state[2 + 4 * c] = (byte)(a0 ^ a1 ^ _gf.Multiply(a2, 2) ^ _gf.Multiply(a3, 3));
            state[3 + 4 * c] = (byte)(_gf.Multiply(a0, 3) ^ a1 ^ a2 ^ _gf.Multiply(a3, 2));
        }
    }

    public void InvMixColumns(byte[] state)
    {
        for (int c = 0; c < _nb; c++)
        {
            byte a0 = state[0 + 4 * c];
            byte a1 = state[1 + 4 * c];
            byte a2 = state[2 + 4 * c];
            byte a3 = state[3 + 4 * c];

            state[0 + 4 * c] = (byte)(_gf.Multiply(a0, 0x0E) ^ _gf.Multiply(a1, 0x0B) ^ _gf.Multiply(a2, 0x0D) ^ _gf.Multiply(a3, 0x09));
            state[1 + 4 * c] = (byte)(_gf.Multiply(a0, 0x09) ^ _gf.Multiply(a1, 0x0E) ^ _gf.Multiply(a2, 0x0B) ^ _gf.Multiply(a3, 0x0D));
            state[2 + 4 * c] = (byte)(_gf.Multiply(a0, 0x0D) ^ _gf.Multiply(a1, 0x09) ^ _gf.Multiply(a2, 0x0E) ^ _gf.Multiply(a3, 0x0B));
            state[3 + 4 * c] = (byte)(_gf.Multiply(a0, 0x0B) ^ _gf.Multiply(a1, 0x0D) ^ _gf.Multiply(a2, 0x09) ^ _gf.Multiply(a3, 0x0E));
        }
    }
}