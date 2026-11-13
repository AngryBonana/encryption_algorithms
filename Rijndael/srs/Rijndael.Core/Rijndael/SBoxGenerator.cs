using Rijndael.Core.GaloisField;

namespace Rijndael.Core.Rijndael;

public sealed class SBoxGenerator
{
    private readonly Gf256 _gf;

    public byte[] SBox { get; }
    public byte[] InvSBox { get; }

    public SBoxGenerator(Gf256 gf)
    {
        _gf = gf;
        SBox = BuildSBox();
        InvSBox = BuildInvSBox();
    }

    private static byte Rotl(byte x, int n) => (byte)(((x << n) | (x >> (8 - n))) & 0xFF);

    private static byte Affine(byte x)
        => (byte)(x ^ Rotl(x, 1) ^ Rotl(x, 2) ^ Rotl(x, 3) ^ Rotl(x, 4) ^ 0x63);

    private byte[] BuildSBox()
    {
        var s = new byte[256];
        s[0] = 0x63;
        for (int x = 1; x < 256; x++)
            s[x] = Affine(_gf.Inverse((byte)x));
        return s;
    }

    private byte[] BuildInvSBox()
    {
        var inv = new byte[256];
        for (int i = 0; i < 256; i++)
            inv[SBox[i]] = (byte)i;
        return inv;
    }
}