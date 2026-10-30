using System;
using System.Numerics;
using RSA.Core.Math;
using RSA.Core.Primality;
using RSA.Core.RSA;
using RSA.Core.Attacks;

Console.WriteLine("Задание 1");
Console.WriteLine($"Лежандр(2/7) = {NumberTheory.LegendreSymbol(2, 7)}");
Console.WriteLine($"Якоби(2/15) = {NumberTheory.JacobiSymbol(2, 15)}");
Console.WriteLine($"НОД классический(12, 18) = {NumberTheory.GcdClassic(12, 18)}");
Console.WriteLine($"НОД бинарный(12, 18) = {NumberTheory.GcdBinary(12, 18)}");

var (g, x, y) = NumberTheory.GcdExtended(240, 46);
Console.WriteLine($"НОД расширенный(240, 46) = {g}, x = {x}, y = {y}, 240*x + 46*y = {240 * x + 46 * y}");

Console.WriteLine($"2^100 mod 1000000007 = {NumberTheory.ModPow(2, 100, 1000000007)}");
Console.WriteLine($"φ(36) по определению = {NumberTheory.EulerPhiByDefinition(36)}");
Console.WriteLine($"φ(36) через факторизацию = {NumberTheory.EulerPhiByFactorization(36)}");
Console.WriteLine($"φ(36) через DFT = {NumberTheory.EulerPhiByDft(36):F4}");
Console.WriteLine($"λ(36) = {NumberTheory.CarmichaelLambda(36)}");

Console.WriteLine("\nЗадание 2");

var tests = new (string name, IProbabilisticPrimalityTest test)[]
{
    ("Ферма", new FermatTest()),
    ("Соловея-Штрассена", new SolovayStrassenTest()),
    ("Миллера-Рабина", new MillerRabinTest()),
};

foreach (var (name, test) in tests)
{
    Console.WriteLine($"{name}: 97 = {test.IsPrime(97, 0.99)}, 100 = {test.IsPrime(100, 0.99)}, 561 = {test.IsPrime(561, 0.99)}");
}

Console.WriteLine("\nЗадание 3");

var keyGen = new RsaCryptoService.KeyGeneratorService(
    RsaCryptoService.PrimalityTestType.MillerRabin, 0.99, 256);
var (n, e, d) = keyGen.GenerateKeyPair();
Console.WriteLine($"n = {n}");
Console.WriteLine($"e = {e}");
Console.WriteLine($"d = {d}");

var message = new BigInteger(123456789);
var cipher = RsaCryptoService.Encrypt(message, e, n);
var decrypted = RsaCryptoService.Decrypt(cipher, d, n);
Console.WriteLine($"m = {message}, c = {cipher}, m' = {decrypted}, совпадает = {message == decrypted}");

Console.WriteLine("\nЗадание 4");

var (vn, ve, vd) = VulnerableKeyGenerator.GenerateWienerVulnerableKey(128);
Console.WriteLine($"уязвимый ключ: n = {vn}, e = {ve}, d = {vd}");

var result = WienerAttackService.Attack(ve, vn);
Console.WriteLine($"найденное d = {result.FoundD}, совпадает = {result.FoundD == vd}");
Console.WriteLine($"φ(n) = {result.Phi}");
Console.WriteLine($"подходящих дробей: {result.Convergents.Count}");