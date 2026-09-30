namespace DES.Core.Abstractions;
 

public interface IRoundFunction
{
    byte[] Transform(byte[] block, byte[] roundKey);
}
