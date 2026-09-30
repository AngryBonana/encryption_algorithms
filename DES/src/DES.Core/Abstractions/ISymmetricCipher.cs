namespace DES.Core.Abstractions;


public interface ISymmetricCipher
{

    int BlockSizeBytes { get; }
    void SetKey(byte[] key);
    byte[] Encrypt(byte[] block);
    byte[] Decrypt(byte[] block);
}