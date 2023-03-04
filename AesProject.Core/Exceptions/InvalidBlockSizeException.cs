namespace AesProject.Core.Exceptions;

public class InvalidBlockSizeException : ArgumentException
{
    public InvalidBlockSizeException(int size)
        : base($"Incorrect AES block size! Wanted: 128bits, Got: {size * 8}bits")
    {
    }
}