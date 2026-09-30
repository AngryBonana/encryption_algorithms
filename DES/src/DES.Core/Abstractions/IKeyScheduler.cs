namespace DES.Core.Abstractions;
 

public interface IKeyScheduler
{

    byte[][] GenerateRoundKeys(byte[] key);
}
