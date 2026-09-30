using DES.Core.Abstractions;
using DES.Core.Ciphers;
using DES.Core.BitPermutation;
using DES.Core.Tables;

namespace DES.Core;

public sealed class DesCipher : ISymmetricCipher
{
    private const int Rounds = 16;

    private readonly FeistelNetwork _feistel;
    private readonly DesKeyScheduler _keyScheduler = new();
    private readonly DesRoundFunction _roundFunction = new();

    public int BlockSizeBytes => 8;

    public DesCipher()
    {
        _feistel = new FeistelNetwork(
            _keyScheduler,
            _roundFunction,
            blockSizeBytes: 8,
            rounds: Rounds,
            swapAfterLastRound: true);
    }

    public void SetKey(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length != 8)
            throw new ArgumentException("Ключ DES должен быть длиной 8 байт (64 бита).", nameof(key));

        _feistel.SetKey(key);
    }

    public byte[] Encrypt(byte[] block)
    {
        ArgumentNullException.ThrowIfNull(block);
        if (block.Length != 8)
            throw new ArgumentException("Блок DES должен быть длиной 8 байт (64 бита).", nameof(block));

        byte[] permuted = BitPermuter.Permute(block, DesTables.IP, BitOrder.MsbFirst, 1);

        byte[] feistelResult = _feistel.Encrypt(permuted);

        return BitPermuter.Permute(feistelResult, DesTables.FP, BitOrder.MsbFirst, 1);
    }

    public byte[] Decrypt(byte[] block)
    {
        ArgumentNullException.ThrowIfNull(block);
        if (block.Length != 8)
            throw new ArgumentException("Блок DES должен быть длиной 8 байт (64 бита).", nameof(block));

        byte[] permuted = BitPermuter.Permute(block, DesTables.IP, BitOrder.MsbFirst, 1);

        byte[] feistelResult = _feistel.Decrypt(permuted);

        return BitPermuter.Permute(feistelResult, DesTables.FP, BitOrder.MsbFirst, 1);
    }
}