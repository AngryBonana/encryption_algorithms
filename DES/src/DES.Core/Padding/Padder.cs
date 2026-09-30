using System.Security.Cryptography;

namespace CryptoLab.Core.Padding;


public static class Padder
{
    public static byte[] Pad(byte[] data, int blockSize, PaddingMode mode)
    {
        ArgumentNullException.ThrowIfNull(data);
        if (blockSize <= 0 || blockSize > 255)
            throw new ArgumentOutOfRangeException(nameof(blockSize),
                "Block size must be between 1 and 255!");

        int remainder = data.Length % blockSize;
        int padLength = (mode == PaddingMode.Zeros && remainder == 0) ? 0 : blockSize - remainder;

        if (padLength == 0)
            return (byte[])data.Clone();

        byte[] result = new byte[data.Length + padLength];
        Array.Copy(data, result, data.Length);

        switch (mode)
        {
            case PaddingMode.Zeros:
                break;

            case PaddingMode.ANSI_X923:
                result[^1] = (byte)padLength;
                break;

            case PaddingMode.PKCS7:
                for (int i = data.Length; i < result.Length; i++)
                    result[i] = (byte)padLength;
                break;

            case PaddingMode.ISO10126:
                if (padLength > 1)
                    RandomNumberGenerator.Fill(result.AsSpan(data.Length, padLength - 1));
                result[^1] = (byte)padLength;
                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(mode));
        }

        return result;
    }

    public static byte[] Unpad(byte[] data, PaddingMode mode)
    {
        ArgumentNullException.ThrowIfNull(data);

        if (mode == PaddingMode.Zeros)
        {
            int end = data.Length;
            while (end > 0 && data[end - 1] == 0)
                end--;
            return data[..end];
        }

        
        if (data.Length == 0)
            throw new Exception();

        int padLength = data[^1];
        if (padLength == 0 || padLength > data.Length)
            throw new Exception();

        switch (mode)
        {
            case PaddingMode.PKCS7:
                for (int i = data.Length - padLength; i < data.Length; i++)
                    if (data[i] != padLength) throw new Exception();
                break;

            case PaddingMode.ANSI_X923:
                for (int i = data.Length - padLength; i < data.Length - 1; i++)
                    if (data[i] != 0) throw new Exception();
                break;

            case PaddingMode.ISO10126:
                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(mode));
        }

        return data[..^padLength];
        
    }
}