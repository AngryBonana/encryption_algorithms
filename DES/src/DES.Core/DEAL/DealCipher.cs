using DES.Core.Abstractions;
using DES.Core.Ciphers;

namespace DES.Core.Deal;


public sealed class DealCipher : ISymmetricCipher
{
    private readonly FeistelNetwork _feistel;
    private readonly DesRoundFunctionAdapter _roundFunction;
    private readonly DealKeyScheduler _keyScheduler;

    public int BlockSizeBytes => 16;

    public DealCipher()
    {
        _roundFunction = new DesRoundFunctionAdapter(() => new DesCipher());

        _keyScheduler = new DealKeyScheduler(new DesCipher());

        _feistel = new FeistelNetwork(
            _keyScheduler,
            _roundFunction,
            blockSizeBytes: 16,
            rounds: 6,
            swapAfterLastRound: true);
    }

    public void SetKey(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);

        int keyBits = key.Length * 8;
        if (keyBits != 128 && keyBits != 192 && keyBits != 256)
            throw new ArgumentException(
                "Ключ DEAL должен быть 128, 192 или 256 бит (16, 24 или 32 байта).",
                nameof(key));

        _feistel.SetKey(key);
    }

    public byte[] Encrypt(byte[] block)
    {
        ArgumentNullException.ThrowIfNull(block);
        if (block.Length != 16)
            throw new ArgumentException(
                "Блок DEAL должен быть 16 байт (128 бит).", nameof(block));

        return _feistel.Encrypt(block);
    }

    public byte[] Decrypt(byte[] block)
    {
        ArgumentNullException.ThrowIfNull(block);
        if (block.Length != 16)
            throw new ArgumentException(
                "Блок DEAL должен быть 16 байт (128 бит).", nameof(block));

        return _feistel.Decrypt(block);
    }
}