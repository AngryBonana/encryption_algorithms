using Rijndael.Core;
using Rijndael.Core.GaloisField;
using Rijndael.Core.Modes;
using Rijndael.Core.Padding;
using Rijndael.Core.Rijndael;



string inputFile = "../../samples/patriot.mp4";
string encryptedFile = "encrypted.bin";
string decryptedFile = "decrypted.mp4";

if (!File.Exists(inputFile))
{
    throw new FileNotFoundException("Нет такого файла!");
}

byte[] randomBytes = new byte[50];
new Random(1).NextBytes(randomBytes);

byte[] moduli = {0x1B, 0x2B, 0x2D};

int[] blockSizes = {128, 192, 256};

int[] keySizes = {128, 192, 256};

Console.WriteLine("Массив псевдослучайных байт (50 байт)");
foreach (var mode in new[] {CipherMode.CBC, CipherMode.CTR, CipherMode.PCBC, CipherMode.CFB, CipherMode.OFB})
{
    foreach (var padding in new[] {PaddingMode.PKCS7, PaddingMode.ANSI_X923, PaddingMode.ISO10126})
    {
        var gf = new Gf256(0x1B);
        var cipher = new RijndaelCipher(gf, 128);
        var key = GenerateRandomKey(128 / 8);
        var iv = GenerateRandomKey(16);

        var ctx = new SymmetricCryptoContext(cipher, key, mode, padding, iv);

        ctx.Encrypt(randomBytes, out byte[] enc);
        ctx.Decrypt(enc, out byte[] dec);

        bool isOk = randomBytes.AsSpan().SequenceEqual(dec);
        Console.WriteLine($"Режим: {mode,-4} | Набивка: {padding,-10} | Успех: {isOk}");
    }
}

Console.WriteLine("\nФайл");
{
    byte modulus = moduli[0];
    int blockBits = blockSizes[0];
    int keyBits = keySizes[0];

    var mode = CipherMode.CTR;

    var padding = PaddingMode.ISO10126;

    var gf = new Gf256(modulus);

    var cipher = new RijndaelCipher(gf, blockBits);

    byte[] key = GenerateRandomKey(keyBits / 8);
    byte[] iv = GenerateRandomKey(blockBits / 8);

    var ctx = new SymmetricCryptoContext(cipher, key, mode, padding, iv);

    ctx.Encrypt(inputFile, encryptedFile);
    ctx.Decrypt(encryptedFile, decryptedFile);

    byte[] original = File.ReadAllBytes(inputFile);
    byte[] decrypted = File.ReadAllBytes(decryptedFile);
    bool success = original.AsSpan().SequenceEqual(decrypted);

    Console.WriteLine($"Файлы совпадают: {success}");
}
            

static byte[] GenerateRandomKey(int length)
{
    var key = new byte[length];
    new Random(123 + length).NextBytes(key);
    return key;
}