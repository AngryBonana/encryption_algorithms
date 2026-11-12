using Rijndael.Core.Abstractions;
using Rijndael.Core.GaloisField;

namespace Rijndael.Core.Rijndael;

public sealed class RijndaelCipher : ISymmetricCipher
{
    private readonly Gf256 _gf;
    private readonly SBoxGenerator _sboxGen;
    private readonly RijndaelRoundFunction _roundFn;
    private byte[][] _roundKeys = Array.Empty<byte[]>();
    private int _nr;
    private readonly int _nb;

    public int BlockSizeBytes { get; }

    public RijndaelCipher(Gf256 gf, int blockSizeBits = 128)
    {
        if (blockSizeBits != 128 && blockSizeBits != 192 && blockSizeBits != 256)
            throw new ArgumentException("Длина блока: 128, 192 или 256 бит.");

        _gf = gf;
        _nb = blockSizeBits / 32;
        BlockSizeBytes = blockSizeBits / 8;
        _sboxGen = new SBoxGenerator(_gf);
        _roundFn = new RijndaelRoundFunction(_gf, _sboxGen, _nb);
    }

    public void SetKey(byte[] key)
    {
        if (key.Length != 16 && key.Length != 24 && key.Length != 32)
            throw new ArgumentException("Длина ключа: 128, 192 или 256 бит.");

        int nk = key.Length / 4;
        _nr = Math.Max(_nb, nk) + 6;

        var scheduler = new RijndaelKeyScheduler(_gf, _sboxGen, _nb);
        _roundKeys = scheduler.GenerateRoundKeys(key);
    }

    public byte[] Encrypt(byte[] block)
    {
        if (block.Length != BlockSizeBytes)
            throw new ArgumentException("Неверный размер блока.");

        var state = (byte[])block.Clone();
        _roundFn.AddRoundKey(state, _roundKeys[0]);

        for (int round = 1; round < _nr; round++)
        {
            _roundFn.SubBytes(state);
            _roundFn.ShiftRows(state);
            _roundFn.MixColumns(state);
            _roundFn.AddRoundKey(state, _roundKeys[round]);
        }

        _roundFn.SubBytes(state);
        _roundFn.ShiftRows(state);
        _roundFn.AddRoundKey(state, _roundKeys[_nr]);

        return state;
    }

    public byte[] Decrypt(byte[] block)
    {
        if (block.Length != BlockSizeBytes)
            throw new ArgumentException("Неверный размер блока.");

        var state = (byte[])block.Clone();
        _roundFn.AddRoundKey(state, _roundKeys[_nr]);

        for (int round = _nr - 1; round > 0; round--)
        {
            _roundFn.InvShiftRows(state);
            _roundFn.InvSubBytes(state);
            _roundFn.AddRoundKey(state, _roundKeys[round]);
            _roundFn.InvMixColumns(state);
        }

        _roundFn.InvShiftRows(state);
        _roundFn.InvSubBytes(state);
        _roundFn.AddRoundKey(state, _roundKeys[0]);

        return state;
    }
}