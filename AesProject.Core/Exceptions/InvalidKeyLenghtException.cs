namespace AesProject.Core.Exceptions;

public class InvalidKeyLenghtException : ArgumentException
{
    public InvalidKeyLenghtException(int expectedKeyLenght, int keyLenght)
        : base($"Invalid AES key lenght! Wanted: {expectedKeyLenght * 8}bits. Got: {keyLenght * 8}bits.")
    {
    }

    public InvalidKeyLenghtException() :
        base("Invalid AES key lenght! Correct lengths: 128, 192, 256 bits.")
    {
    }
}