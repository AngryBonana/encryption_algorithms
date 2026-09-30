using DES.Core.Abstractions;

namespace DES.Core.Ciphers;

public sealed class FeistelNetwork : ISymmetricCipher
{
    private readonly IKeyScheduler _keyScheduler;
    private readonly IRoundFunction _roundFunction;
    private readonly int _rounds;
    private readonly bool _swapAfterLastRound;

    private byte[]? _key;
    private byte[][]? _roundKeys;

    public int BlockSizeBytes { get; }

    public FeistelNetwork(
        IKeyScheduler keyScheduler,
        IRoundFunction roundFunction,
        int blockSizeBytes,
        int rounds,
        bool swapAfterLastRound = true)
    {
        _keyScheduler = keyScheduler ?? throw new ArgumentNullException(nameof(keyScheduler));
        _roundFunction = roundFunction ?? throw new ArgumentNullException(nameof(roundFunction));

        if (blockSizeBytes <= 0 || blockSizeBytes % 2 != 0)
            throw new ArgumentOutOfRangeException(nameof(blockSizeBytes),
                "Размер блока должен быть положительным чётным числом.");

        if (rounds <= 0)
            throw new ArgumentOutOfRangeException(nameof(rounds),
                "Количество раундов должно быть положительным.");

        BlockSizeBytes = blockSizeBytes;
        _rounds = rounds;
        _swapAfterLastRound = swapAfterLastRound;
    }

    public void SetKey(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);

        _key = (byte[])key.Clone();
        _roundKeys = _keyScheduler.GenerateRoundKeys(_key);

        if (_roundKeys is null || _roundKeys.Length != _rounds)
            throw new InvalidOperationException(
                $"Планировщик ключей вернул {_roundKeys?.Length ?? 0} раундовых ключей, ожидалось {_rounds}.");
    }

    public byte[] Encrypt(byte[] block)
    {
        ArgumentNullException.ThrowIfNull(block);
        EnsureKeySet();
        if (block.Length != BlockSizeBytes)
            throw new ArgumentException(
                $"Длина блока должна быть {BlockSizeBytes} байт.", nameof(block));

        (byte[] left, byte[] right) = SplitBlock(block);

        for (int round = 0; round < _rounds; round++)
        {
            byte[] f = _roundFunction.Transform(right, _roundKeys![round]);
            byte[] newRight = Xor(left, f);
            left = right;
            right = newRight;
        }

        return _swapAfterLastRound
            ? Combine(right, left)
            : Combine(left, right);
    }

    public byte[] Decrypt(byte[] block)
    {
        ArgumentNullException.ThrowIfNull(block);
        EnsureKeySet();
        if (block.Length != BlockSizeBytes)
            throw new ArgumentException(
                $"Длина блока должна быть {BlockSizeBytes} байт.", nameof(block));

        (byte[] left, byte[] right) = SplitBlock(block);

        if (_swapAfterLastRound)
            (left, right) = (right, left);

        for (int round = _rounds - 1; round >= 0; round--)
        {
            byte[] f = _roundFunction.Transform(left, _roundKeys![round]);
            byte[] newLeft = Xor(right, f);
            right = left;
            left = newLeft;
        }

        return Combine(left, right);
    }


    private void EnsureKeySet()
    {
        if (_roundKeys is null)
            throw new InvalidOperationException("Ключ не установлен. Вызовите SetKey перед использованием.");
    }

    private (byte[] left, byte[] right) SplitBlock(byte[] block)
    {
        int half = block.Length / 2;
        byte[] left = new byte[half];
        byte[] right = new byte[half];
        Array.Copy(block, 0, left, 0, half);
        Array.Copy(block, half, right, 0, half);
        return (left, right);
    }

    private static byte[] Combine(byte[] left, byte[] right)
    {
        byte[] result = new byte[left.Length + right.Length];
        Array.Copy(left, 0, result, 0, left.Length);
        Array.Copy(right, 0, result, left.Length, right.Length);
        return result;
    }

    private static byte[] Xor(byte[] a, byte[] b)
    {
        if (a.Length != b.Length)
            throw new ArgumentException("Длины операндов XOR должны совпадать.");
        byte[] result = new byte[a.Length];
        for (int i = 0; i < a.Length; i++)
            result[i] = (byte)(a[i] ^ b[i]);
        return result;
    }
}