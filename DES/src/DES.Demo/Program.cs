using DES.Core;
using DES.Core.Modes;
using DES.Core.Padding;

string inputPath = args.Length > 0 ? args[0] : "input.txt";
string encryptedPath = "encrypted.bin";
string decryptedPath = "decrypted.txt";

if (!File.Exists(inputPath))
{
    Console.WriteLine($"Файл '{inputPath}' не найден — использую Program.cs как источник.");
    inputPath = "Program.cs";
    decryptedPath = "decrypted.cs";

    if (!File.Exists(inputPath))
    {
        Console.WriteLine($"Файл '{inputPath}' тоже не найден. Положите любой файл рядом и запустите снова.");
        return;
    }
}

byte[] key = { 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1 };
byte[] iv  = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

var ctx = new SymmetricCryptoContext(
    new DesCipher(),
    key,
    CipherMode.CBC,
    PaddingMode.PKCS7,
    iv);

Console.WriteLine($"Вход: {inputPath}");
Console.WriteLine($"Размер: {new FileInfo(inputPath).Length:N0} байт");
Console.WriteLine();


var sw = System.Diagnostics.Stopwatch.StartNew();
await ctx.EncryptAsync(inputPath, encryptedPath);
sw.Stop();
Console.WriteLine($"Шифрование: {encryptedPath} ({new FileInfo(encryptedPath).Length:N0} байт, {sw.ElapsedMilliseconds} мс)");


sw.Restart();
await ctx.DecryptAsync(encryptedPath, decryptedPath);
sw.Stop();
Console.WriteLine($"Расшифровка: {decryptedPath} ({new FileInfo(decryptedPath).Length:N0} байт, {sw.ElapsedMilliseconds} мс)");


byte[] original  = await File.ReadAllBytesAsync(inputPath);
byte[] decrypted = await File.ReadAllBytesAsync(decryptedPath);

bool equal = original.AsSpan().SequenceEqual(decrypted);
Console.WriteLine();
Console.WriteLine(equal
    ? "Расшифрованный файл совпадает с исходным."
    : "Расшифрованный файл НЕ совпадает с исходным.");