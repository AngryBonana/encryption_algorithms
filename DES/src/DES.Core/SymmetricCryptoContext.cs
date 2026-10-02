using System.Numerics;
using DES.Core.Abstractions;
using DES.Core.Modes;
using DES.Core.Padding;

namespace DES.Core;

public sealed class SymmetricCryptoContext
{
    #region Fields
    private readonly ISymmetricCipher _cipher;
    private readonly CipherMode _mode;
    private readonly PaddingMode _padding;
    private readonly byte[]? _iv;
    private readonly int _blockSize;
    private readonly byte[]? _delta;

    private byte[]? _streamFeedback;
    private long _streamBlockIndex;

    private const int StreamBufferBytes = 1 << 20;

    #endregion

    #region Constructors
    public SymmetricCryptoContext(
        ISymmetricCipher cipher,
        byte[] key,
        CipherMode mode,
        PaddingMode padding,
        byte[]? iv = null,
        params object[] modeParameters)
    {
        _cipher = cipher ?? throw new ArgumentNullException(nameof(cipher));
        ArgumentNullException.ThrowIfNull(key);

        _cipher.SetKey(key);
        _mode = mode;
        _padding = padding;
        _blockSize = cipher.BlockSizeBytes;

        if (mode != CipherMode.ECB)
        {
            if (iv is null)
                throw new ArgumentException($"Режим {mode} требует вектор инициализации.", nameof(iv));
            if (iv.Length != _blockSize)
                throw new ArgumentException(
                    $"Длина IV ({iv.Length}) должна совпадать с размером блока ({_blockSize}).", nameof(iv));
        }
        _iv = iv;

        if (mode == CipherMode.RandomDelta)
        {
            if (modeParameters.Length == 0 || modeParameters[0] is not byte[] delta)
                throw new ArgumentException(
                    "Режим RandomDelta требует дополнительный параметр Delta (byte[]) первым элементом modeParameters.",
                    nameof(modeParameters));
            if (delta.Length != _blockSize)
                throw new ArgumentException($"Delta должна иметь длину {_blockSize} байт.", nameof(modeParameters));
            _delta = delta;
        }
    }

    #endregion

    #region Public_API
    public void Encrypt(byte[] data, out byte[] result) => result = EncryptCore(data);

    public void Decrypt(byte[] data, out byte[] result) => result = DecryptCore(data);

    public Task<byte[]> EncryptAsync(byte[] data) => Task.Run(() => EncryptCore(data));

    public Task<byte[]> DecryptAsync(byte[] data) => Task.Run(() => DecryptCore(data));


    
    public void Encrypt(string inputFilePath, string outputFilePath) =>
        EncryptAsync(inputFilePath, outputFilePath).GetAwaiter().GetResult();

    public void Decrypt(string inputFilePath, string outputFilePath) =>
        DecryptAsync(inputFilePath, outputFilePath).GetAwaiter().GetResult();

    public async Task EncryptAsync(string inputFilePath, string outputFilePath)
    {
        byte[] data = await File.ReadAllBytesAsync(inputFilePath);
        byte[] result = await EncryptAsync(data);
        await File.WriteAllBytesAsync(outputFilePath, result);
    }

    public async Task DecryptAsync(string inputFilePath, string outputFilePath)
    {
        byte[] data = await File.ReadAllBytesAsync(inputFilePath);
        byte[] result = await DecryptAsync(data);
        await File.WriteAllBytesAsync(outputFilePath, result);
    }


    public byte[] EncryptStream(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        using var input  = new MemoryStream(data);
        using var output = new MemoryStream();
        Encrypt(input, output);
        return output.ToArray();
    }

    public byte[] DecryptStream(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        using var input  = new MemoryStream(data);
        using var output = new MemoryStream();
        Decrypt(input, output);
        return output.ToArray();
    }

    public void Encrypt(Stream input, Stream output, CancellationToken ct = default)
    {
        int blockSize = _blockSize;
        int bufSize = Math.Max(StreamBufferBytes / blockSize * blockSize, blockSize);

        ResetStreamState();

        byte[] buffer = new byte[bufSize + blockSize];
        int carry = 0;

        int read;
        while ((read = input.Read(buffer, carry, bufSize)) > 0)
        {
            ct.ThrowIfCancellationRequested();
            int total = carry + read;
            int fullBlocks = total / blockSize * blockSize;

            for (int offset = 0; offset < fullBlocks; offset += blockSize)
            {
                byte[] block = new byte[blockSize];
                Array.Copy(buffer, offset, block, 0, blockSize);
                byte[] enc = EncryptBlock(block);
                output.Write(enc, 0, enc.Length);
            }

            carry = total - fullBlocks;
            if (carry > 0)
                Array.Copy(buffer, fullBlocks, buffer, 0, carry);
        }

        byte[] tail = new byte[carry];
        Array.Copy(buffer, 0, tail, 0, carry);
        byte[] padded = Padder.Pad(tail, blockSize, _padding);

        for (int offset = 0; offset < padded.Length; offset += blockSize)
        {
            byte[] block = new byte[blockSize];
            Array.Copy(padded, offset, block, 0, blockSize);
            byte[] enc = EncryptBlock(block);
            output.Write(enc, 0, enc.Length);
        }
    }

    public void Decrypt(Stream input, Stream output, CancellationToken ct = default)
    {
        int blockSize = _blockSize;
        int bufSize = Math.Max(StreamBufferBytes / blockSize * blockSize, blockSize);

        ResetStreamState();

        byte[] buffer = new byte[bufSize + blockSize];
        int carry = 0;
        byte[]? pending = null;

        int read;
        while ((read = input.Read(buffer, carry, bufSize)) > 0)
        {
            ct.ThrowIfCancellationRequested();
            int total = carry + read;
            int fullBlocks = total / blockSize * blockSize;

            for (int offset = 0; offset < fullBlocks; offset += blockSize)
            {
                byte[] block = new byte[blockSize];
                Array.Copy(buffer, offset, block, 0, blockSize);
                byte[] dec = DecryptBlock(block);

                if (pending is not null)
                    output.Write(pending, 0, pending.Length);

                pending = dec;
            }

            carry = total - fullBlocks;
            if (carry > 0)
                Array.Copy(buffer, fullBlocks, buffer, 0, carry);
        }

        if (carry != 0)
            throw new ArgumentException("Длина шифротекста не кратна размеру блока.", nameof(input));
        if (pending is null)
            throw new ArgumentException("Пустой шифротекст.", nameof(input));

        byte[] unpadded = Padder.Unpad(pending, _padding);
        output.Write(unpadded, 0, unpadded.Length);
    }

    #endregion

    #region Core

    private byte[] EncryptCore(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);

        byte[] padded = Padder.Pad(data, _blockSize, _padding);
        byte[][] blocks = SplitIntoBlocks(padded);

        byte[][] encrypted = _mode switch
        {
            Modes.CipherMode.ECB => EncryptEcb(blocks),
            Modes.CipherMode.CBC => EncryptCbc(blocks),
            Modes.CipherMode.PCBC => EncryptPcbc(blocks),
            Modes.CipherMode.CFB => EncryptCfb(blocks),
            Modes.CipherMode.OFB => EncryptOfb(blocks),
            Modes.CipherMode.CTR => EncryptCtr(blocks),
            Modes.CipherMode.RandomDelta => EncryptRandomDelta(blocks),
            _ => throw new NotSupportedException($"Режим {_mode} не поддерживается.")
        };

        return Combine(encrypted);
    }

    private byte[] DecryptCore(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        if (data.Length % _blockSize != 0)
            throw new ArgumentException("Длина шифротекста должна быть кратна размеру блока.", nameof(data));

        byte[][] blocks = SplitIntoBlocks(data);

        byte[][] decrypted = _mode switch
        {
            Modes.CipherMode.ECB => DecryptEcb(blocks),
            Modes.CipherMode.CBC => DecryptCbc(blocks),
            Modes.CipherMode.PCBC => DecryptPcbc(blocks),
            Modes.CipherMode.CFB => DecryptCfb(blocks),
            Modes.CipherMode.OFB => DecryptOfb(blocks),
            Modes.CipherMode.CTR => DecryptCtr(blocks),
            Modes.CipherMode.RandomDelta => DecryptRandomDelta(blocks),
            _ => throw new NotSupportedException($"Режим {_mode} не поддерживается.")
        };

        byte[] combined = Combine(decrypted);
        return Padder.Unpad(combined, _padding);
    }

    private byte[] EncryptBlock(byte[] block)
    {
        EnsureStreamState();
        switch (_mode)
        {
            case CipherMode.ECB:
                return _cipher.Encrypt(block);

            case CipherMode.CBC:
            {
                byte[] enc = _cipher.Encrypt(Xor(block, _streamFeedback!));
                _streamFeedback = enc;
                return enc;
            }
            case CipherMode.PCBC:
            {
                byte[] enc = _cipher.Encrypt(Xor(block, _streamFeedback!));
                _streamFeedback = Xor(block, enc);
                return enc;
            }
            case CipherMode.CFB:
            {
                byte[] ks = _cipher.Encrypt(_streamFeedback!);
                byte[] res = Xor(block, ks);
                _streamFeedback = res;
                return res;
            }
            case CipherMode.OFB:
            {
                _streamFeedback = _cipher.Encrypt(_streamFeedback!);
                return Xor(block, _streamFeedback);
            }
            case CipherMode.CTR:
            {
                byte[] counter = AddModBlockSize(_iv!, IntToBlock(_streamBlockIndex++, _blockSize));
                return Xor(block, _cipher.Encrypt(counter));
            }
            case CipherMode.RandomDelta:
            {
                byte[] mask = RandomDeltaMask(_streamBlockIndex++);
                return Xor(_cipher.Encrypt(mask), block);
            }
            default:
                throw new NotSupportedException($"Режим {_mode} не поддерживается.");
        }
    }

    private byte[] DecryptBlock(byte[] block)
    {
        EnsureStreamState();
        switch (_mode)
        {
            case CipherMode.ECB:
                return _cipher.Decrypt(block);

            case CipherMode.CBC:
            {
                byte[] dec = _cipher.Decrypt(block);
                byte[] res = Xor(dec, _streamFeedback!);
                _streamFeedback = block;
                return res;
            }
            case CipherMode.PCBC:
            {
                byte[] dec = _cipher.Decrypt(block);
                byte[] res = Xor(dec, _streamFeedback!);
                _streamFeedback = Xor(block, res);
                return res;
            }
            case CipherMode.CFB:
            {
                byte[] ks = _cipher.Encrypt(_streamFeedback!);
                byte[] res = Xor(block, ks);
                _streamFeedback = block;
                return res;
            }
            case CipherMode.OFB:
            {
                _streamFeedback = _cipher.Encrypt(_streamFeedback!);
                return Xor(block, _streamFeedback);
            }
            case CipherMode.CTR:
            {
                byte[] counter = AddModBlockSize(_iv!, IntToBlock(_streamBlockIndex++, _blockSize));
                return Xor(block, _cipher.Encrypt(counter));
            }
            case CipherMode.RandomDelta:
            {
                byte[] mask = RandomDeltaMask(_streamBlockIndex++);
                return Xor(_cipher.Encrypt(mask), block);
            }
            default:
                throw new NotSupportedException($"Режим {_mode} не поддерживается.");
        }
    }

    private void EnsureStreamState()
    {
        if (_mode is CipherMode.CBC or CipherMode.PCBC or CipherMode.CFB or CipherMode.OFB
            && _streamFeedback is null)
        {
            throw new InvalidOperationException(
                "Состояние потокового режима не инициализировано. Вызовите ResetStreamState().");
        }
    }

    #endregion

    #region Cipher_Modes
    private byte[][] EncryptEcb(byte[][] blocks)
    {
        var result = new byte[blocks.Length][];
        Parallel.For(0, blocks.Length, i => result[i] = _cipher.Encrypt(blocks[i]));
        return result;
    }

    private byte[][] DecryptEcb(byte[][] blocks)
    {
        var result = new byte[blocks.Length][];
        Parallel.For(0, blocks.Length, i => result[i] = _cipher.Decrypt(blocks[i]));
        return result;
    }


    private byte[][] EncryptCbc(byte[][] blocks)
    {
        var result = new byte[blocks.Length][];
        byte[] prev = _iv!;
        for (int i = 0; i < blocks.Length; i++)
        {
            result[i] = _cipher.Encrypt(Xor(blocks[i], prev));
            prev = result[i];
        }
        return result;
    }

    private byte[][] DecryptCbc(byte[][] blocks)
    {
        var result = new byte[blocks.Length][];
        Parallel.For(0, blocks.Length, i =>
        {
            byte[] prev = i == 0 ? _iv! : blocks[i - 1];
            result[i] = Xor(_cipher.Decrypt(blocks[i]), prev);
        });
        return result;
    }


    private byte[][] EncryptPcbc(byte[][] blocks)
    {
        var result = new byte[blocks.Length][];
        byte[] feedback = _iv!;
        for (int i = 0; i < blocks.Length; i++)
        {
            result[i] = _cipher.Encrypt(Xor(blocks[i], feedback));
            feedback = Xor(blocks[i], result[i]);
        }
        return result;
    }

    private byte[][] DecryptPcbc(byte[][] blocks)
    {
        var result = new byte[blocks.Length][];
        byte[] feedback = _iv!;
        for (int i = 0; i < blocks.Length; i++)
        {
            result[i] = Xor(_cipher.Decrypt(blocks[i]), feedback);
            feedback = Xor(blocks[i], result[i]);
        }
        return result;
    }


    private byte[][] EncryptCfb(byte[][] blocks)
    {
        var result = new byte[blocks.Length][];
        byte[] prev = _iv!;
        for (int i = 0; i < blocks.Length; i++)
        {
            byte[] keystream = _cipher.Encrypt(prev);
            result[i] = Xor(blocks[i], keystream);
            prev = result[i];
        }
        return result;
    }

    private byte[][] DecryptCfb(byte[][] blocks)
    {
        var result = new byte[blocks.Length][];
        Parallel.For(0, blocks.Length, i =>
        {
            byte[] prev = i == 0 ? _iv! : blocks[i - 1];
            byte[] keystream = _cipher.Encrypt(prev);
            result[i] = Xor(blocks[i], keystream);
        });
        return result;
    }


    private byte[][] EncryptOfb(byte[][] blocks) => ApplyOfbKeystream(blocks);

    private byte[][] DecryptOfb(byte[][] blocks) => ApplyOfbKeystream(blocks);

    private byte[][] ApplyOfbKeystream(byte[][] blocks)
    {
        var result = new byte[blocks.Length][];
        byte[] keystream = _iv!;
        for (int i = 0; i < blocks.Length; i++)
        {
            keystream = _cipher.Encrypt(keystream);
            result[i] = Xor(blocks[i], keystream);
        }
        return result;
    }


    private byte[][] EncryptCtr(byte[][] blocks) => ApplyCtrKeystream(blocks);

    private byte[][] DecryptCtr(byte[][] blocks) => ApplyCtrKeystream(blocks);

    private byte[][] ApplyCtrKeystream(byte[][] blocks)
    {
        var result = new byte[blocks.Length][];
        Parallel.For(0, blocks.Length, i =>
        {
            byte[] counter = AddModBlockSize(_iv!, IntToBlock(i, _blockSize));
            byte[] keystream = _cipher.Encrypt(counter);
            result[i] = Xor(blocks[i], keystream);
        });
        return result;
    }

    private byte[][] EncryptRandomDelta(byte[][] blocks)
    {
        var result = new byte[blocks.Length][];
        Parallel.For(0, blocks.Length, i =>
        {
            byte[] mask = RandomDeltaMask(i);
            result[i] = Xor(blocks[i], _cipher.Encrypt(mask));
        });
        return result;
    }

    private byte[][] DecryptRandomDelta(byte[][] blocks)
    {
        var result = new byte[blocks.Length][];
        Parallel.For(0, blocks.Length, i =>
        {
            byte[] mask = RandomDeltaMask(i);
            result[i] = Xor(_cipher.Encrypt(mask), blocks[i]);
        });
        return result;
    }

    private byte[] RandomDeltaMask(int blockIndex) =>
        AddModBlockSize(_iv!, MultiplyModBlockSize(_delta!, blockIndex));

    private byte[] RandomDeltaMask(long blockIndex) =>
        AddModBlockSize(_iv!, MultiplyModBlockSize(_delta!, blockIndex));

    
    #endregion

    #region Helpers
    private byte[][] SplitIntoBlocks(byte[] data)
    {
        int blockCount = data.Length / _blockSize;
        var blocks = new byte[blockCount][];
        for (int i = 0; i < blockCount; i++)
        {
            blocks[i] = new byte[_blockSize];
            Array.Copy(data, i * _blockSize, blocks[i], 0, _blockSize);
        }
        return blocks;
    }

    private static byte[] Combine(byte[][] blocks)
    {
        int blockSize = blocks.Length > 0 ? blocks[0].Length : 0;
        byte[] result = new byte[blocks.Length * blockSize];
        for (int i = 0; i < blocks.Length; i++)
            Array.Copy(blocks[i], 0, result, i * blockSize, blockSize);
        return result;
    }

    private static byte[] Xor(byte[] a, byte[] b)
    {
        byte[] result = new byte[a.Length];
        for (int i = 0; i < a.Length; i++)
            result[i] = (byte)(a[i] ^ b[i]);
        return result;
    }

    private static byte[] AddModBlockSize(byte[] a, byte[] b)
    {
        var x = new BigInteger(a, isUnsigned: true, isBigEndian: true);
        var y = new BigInteger(b, isUnsigned: true, isBigEndian: true);
        var mod = BigInteger.One << (a.Length * 8);
        return ToFixedLengthBigEndian((x + y) % mod, a.Length);
    }

    private static byte[] MultiplyModBlockSize(byte[] a, long scalar)
    {
        var x = new BigInteger(a, isUnsigned: true, isBigEndian: true);
        var mod = BigInteger.One << (a.Length * 8);
        return ToFixedLengthBigEndian((x * scalar) % mod, a.Length);
    }

    private static byte[] IntToBlock(long value, int length) =>
        ToFixedLengthBigEndian(new BigInteger(value), length);

    private static byte[] ToFixedLengthBigEndian(BigInteger value, int length)
    {
        byte[] bytes = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (bytes.Length == length)
            return bytes;

        byte[] result = new byte[length];
        int copyLength = Math.Min(bytes.Length, length);
        Array.Copy(bytes, bytes.Length - copyLength, result, length - copyLength, copyLength);
        return result;
    }

    private void ResetStreamState()
    {
        _streamFeedback = _iv is null ? null : (byte[])_iv.Clone();
        _streamBlockIndex = 0;
    }

    #endregion
}