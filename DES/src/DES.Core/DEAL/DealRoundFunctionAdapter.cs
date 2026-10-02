using DES.Core.Abstractions;

namespace DES.Core.Deal;

public sealed class DesRoundFunctionAdapter : IRoundFunction
{
    private readonly ThreadLocal<ISymmetricCipher> _des;

    public DesRoundFunctionAdapter(Func<ISymmetricCipher> desFactory)
    {
        ArgumentNullException.ThrowIfNull(desFactory);
        _des = new ThreadLocal<ISymmetricCipher>(desFactory);
    }

    public byte[] Transform(byte[] halfBlock, byte[] roundKey)
    {
        ArgumentNullException.ThrowIfNull(halfBlock);
        ArgumentNullException.ThrowIfNull(roundKey);

        if (halfBlock.Length != 8)
            throw new ArgumentException("Половина блока DEAL должна быть 8 байт (64 бита).", nameof(halfBlock));

        if (roundKey.Length < 7 || roundKey.Length > 8)
            throw new ArgumentException("Раундовый ключ DEAL должен быть 7 или 8 байт.", nameof(roundKey));

        byte[] key = new byte[8];
        Array.Copy(roundKey, key, Math.Min(roundKey.Length, 8));

        var des = _des.Value!;
        des.SetKey(key);
        return des.Encrypt(halfBlock);
    }
}