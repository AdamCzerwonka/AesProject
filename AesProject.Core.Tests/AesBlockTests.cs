using System.Text;
using AesProject.Core.Exceptions;

namespace AesProject.Core.Tests;

public class AesBlockTests
{
    [Fact]
    public void TestEncrypt_ShouldCorrectlyEncryptBlock_WhenGivenCorrectInput()
    {
        byte[] expectedResult =
            { 0x29, 0xc3, 0x50, 0x5F, 0x57, 0x14, 0x20, 0xF6, 0x40, 0x22, 0x99, 0xB3, 0x1A, 0x02, 0xD7, 0x3A };
        const string clearText = "Two One Nine Two";
        var textBytes = Encoding.ASCII.GetBytes(clearText);

        const string key = "Thats my Kung Fu";
        var keyBytes = Encoding.ASCII.GetBytes(key);

        var block = new AesBlock(textBytes, keyBytes);
        var result = block.Encrypt();

        Assert.Equal(expectedResult, result);
    }

    [Theory]
    [InlineData(new byte[0])]
    [InlineData(new byte[] { 0x00 })]
    public void TestAesBlock_ShouldThrow_WhenGivenIncorrectBlockSize(byte[] input)
    {
        Assert.Throws<InvalidBlockSizeException>(() => new AesBlock(input, Array.Empty<byte>()));
    }
}