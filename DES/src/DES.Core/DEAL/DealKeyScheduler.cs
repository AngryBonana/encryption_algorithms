using DES.Core.Abstractions;

namespace DES.Core.Deal;


public sealed class DealKeyScheduler : IKeyScheduler
{
    private static readonly byte[] FixedKey =
        { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };

    private static readonly byte[] Constant1 =
        { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    private static readonly byte[] Constant2 =
        { 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    private static readonly byte[] Constant3 =
        { 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };
    private static readonly byte[] Constant4 =
        { 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20 };

    private readonly ISymmetricCipher _des;

    public DealKeyScheduler(ISymmetricCipher des)
    {
        _des = des ?? throw new ArgumentNullException(nameof(des));
    }

    public byte[][] GenerateRoundKeys(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);

        int keyBits = key.Length * 8;
        int rounds;

        if (keyBits == 128) rounds = 6;
        else if (keyBits == 192) rounds = 6;
        else if (keyBits == 256) rounds = 8;
        else throw new ArgumentException(
            "Ключ DEAL должен быть 128, 192 или 256 бит (16, 24 или 32 байта).",
            nameof(key));

        int numKeys = key.Length / 8;
        byte[][] K = new byte[numKeys][];
        for (int i = 0; i < numKeys; i++)
        {
            K[i] = new byte[8];
            Array.Copy(key, i * 8, K[i], 0, 8);
        }

        _des.SetKey(FixedKey);

        byte[][] roundKeys = new byte[rounds][];

        // R1 = E_{R*}(K1)
        roundKeys[0] = _des.Encrypt(K[0]);

        // R2 = E_{R*}(K2 XOR R1)
        roundKeys[1] = _des.Encrypt(Xor(K[1], roundKeys[0]));

        if (rounds == 6)
        {
            if (numKeys == 2)
            {
                roundKeys[2] = _des.Encrypt(Xor(Xor(K[0], roundKeys[1]), Constant1));
                roundKeys[3] = _des.Encrypt(Xor(Xor(K[1], roundKeys[2]), Constant2));
                roundKeys[4] = _des.Encrypt(Xor(Xor(K[0], roundKeys[3]), Constant3));
                roundKeys[5] = _des.Encrypt(Xor(Xor(K[1], roundKeys[4]), Constant4));
            }
            else
            {
                roundKeys[2] = _des.Encrypt(Xor(K[2], roundKeys[1]));
                roundKeys[3] = _des.Encrypt(Xor(Xor(K[0], roundKeys[2]), Constant1));
                roundKeys[4] = _des.Encrypt(Xor(Xor(K[1], roundKeys[3]), Constant2));
                roundKeys[5] = _des.Encrypt(Xor(Xor(K[2], roundKeys[4]), Constant3));
            }
        }
        else
        {
            roundKeys[2] = _des.Encrypt(Xor(K[2], roundKeys[1]));
            roundKeys[3] = _des.Encrypt(Xor(K[3], roundKeys[2]));
            roundKeys[4] = _des.Encrypt(Xor(Xor(K[0], roundKeys[3]), Constant1));
            roundKeys[5] = _des.Encrypt(Xor(Xor(K[1], roundKeys[4]), Constant2));
            roundKeys[6] = _des.Encrypt(Xor(Xor(K[2], roundKeys[5]), Constant3));
            roundKeys[7] = _des.Encrypt(Xor(Xor(K[3], roundKeys[6]), Constant4));
        }

        return roundKeys;
    }

    private static byte[] Xor(byte[] a, byte[] b)
    {
        byte[] result = new byte[a.Length];
        for (int i = 0; i < a.Length; i++)
            result[i] = (byte)(a[i] ^ b[i]);
        return result;
    }
}