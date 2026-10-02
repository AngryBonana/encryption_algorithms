using DES.Core;
using DES.Core.Deal;
using DES.Core.Modes;
using DES.Core.Padding;
using PaddingMode = DES.Core.Padding.PaddingMode;


// Настройки
string inputPath = args.Length > 0 ? args[0] : "input.txt";
string encryptedPath = "encrypted.bin";
string decryptedPath = "decrypted.bin";

// Если входного файла нет — создаём тестовый.
if (!File.Exists(inputPath))
{
    inputPath = "input.txt";
    Console.WriteLine($"Создан тестовый файл: {inputPath}");
}

byte[] key = { 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1,
               0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
byte[] iv  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
               0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

var ctx = new SymmetricCryptoContext(
    new DealCipher(),
    key,
    CipherMode.CBC,
    PaddingMode.PKCS7,
    iv);

Console.WriteLine($"Входной файл: {inputPath} ({new FileInfo(inputPath).Length} байт)");

// 1. Шифруем: файл → файл
ctx.Encrypt(inputPath, encryptedPath);
Console.WriteLine($"Зашифровано: {encryptedPath} ({new FileInfo(encryptedPath).Length} байт)");

// 2. Расшифровываем: файл → файл
ctx.Decrypt(encryptedPath, decryptedPath);
Console.WriteLine($"Расшифровано: {decryptedPath} ({new FileInfo(decryptedPath).Length} байт)");

// 3. Сверяем
byte[] original = await File.ReadAllBytesAsync(inputPath);
byte[] decrypted = await File.ReadAllBytesAsync(decryptedPath);
bool equal = original.AsSpan().SequenceEqual(decrypted);

Console.WriteLine(equal ? "Файлы совпадают." : "Файлы НЕ совпадают.");