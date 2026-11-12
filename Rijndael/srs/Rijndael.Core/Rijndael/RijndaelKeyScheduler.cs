using Rijndael.Core.Abstractions;
using Rijndael.Core.GaloisField;

namespace Rijndael.Core.Rijndael;

public sealed class RijndaelKeyScheduler : IKeyScheduler
{
    private readonly Gf256 _gf;
    private readonly SBoxGenerator _sboxGen;
    private readonly int _nb;

    public RijndaelKeyScheduler(Gf256 gf, SBoxGenerator sboxGen, int nb)
    {
        if (nb != 4 && nb != 6 && nb != 8)
            throw new ArgumentException("Nb должно быть 4, 6 или 8 (128/192/256 бит блока).");
        _gf = gf;
        _sboxGen = sboxGen;
        _nb = nb;
    }

    public byte[][] GenerateRoundKeys(byte[] key)
    {
        int nk = key.Length / 4;
        if (nk != 4 && nk != 6 && nk != 8)
            throw new ArgumentException("Длина ключа должна быть 128, 192 или 256 бит.");

        int nr = Math.Max(_nb, nk) + 6;
        int totalWords = _nb * (nr + 1);

        var w = new byte[totalWords][];

        for (int i = 0; i < nk; i++)
            w[i] = new[] { key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3] };

        byte rcon = 0x01;
        for (int i = nk; i < totalWords; i++)
        {
            var temp = (byte[])w[i - 1].Clone();

            if (i % nk == 0)
            {
                byte t = temp[0];
                temp[0] = temp[1]; temp[1] = temp[2]; temp[2] = temp[3]; temp[3] = t;
                for (int j = 0; j < 4; j++) temp[j] = _sboxGen.SBox[temp[j]];
                temp[0] ^= rcon;
                rcon = _gf.Multiply(rcon, 0x02);
            }
            else if (nk > 6 && i % nk == 4)
            {
                for (int j = 0; j < 4; j++) temp[j] = _sboxGen.SBox[temp[j]];
            }

            w[i] = new byte[4];
            for (int j = 0; j < 4; j++)
                w[i][j] = (byte)(w[i - nk][j] ^ temp[j]);
        }

        var roundKeys = new byte[nr + 1][];
        for (int r = 0; r <= nr; r++)
        {
            roundKeys[r] = new byte[_nb * 4];
            for (int c = 0; c < _nb; c++)
                Array.Copy(w[r * _nb + c], 0, roundKeys[r], c * 4, 4);
        }
        return roundKeys;
    }
}