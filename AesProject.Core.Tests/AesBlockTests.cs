using System.Text;
using AesProject.Core.Exceptions;

namespace AesProject.Core.Tests;

public class AesBlockTests
{
    [Fact]
    public void TestEncrypt_ShouldCorrectlyEncryptBlock_WhenGiven128BitKeyCorrectInput()
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

    [Fact]
    public void TestEncrypt_ShouldCorrectlyEncryptBlock_WhenGiven192BitKeyCorrectInput()
    {
        byte[] expectedResult =
            { 0x83, 0xd0, 0x7d, 0xb6, 0x15, 0xda, 0x00, 0xa8, 0xb2, 0xd4, 0x61, 0xd6, 0x00, 0x4a, 0xf8, 0xcb };
        const string clearText = "Two One Nine Two";
        var textBytes = Encoding.ASCII.GetBytes(clearText);

        const string key = "Thats my Kung Fuaaaaaaaa";
        var keyBytes = Encoding.ASCII.GetBytes(key);

        var block = new AesBlock(textBytes, keyBytes);
        var result = block.Encrypt();

        Assert.Equal(expectedResult, result);
    }
    
    [Fact]
    public void TestEncrypt_ShouldCorrectlyEncryptBlock_WhenGiven256BitKeyCorrectInput()
    {
        byte[] expectedResult =
            { 0x39, 0x8d, 0xff, 0x4e, 0x8b, 0xd9, 0xba, 0x23, 0x35, 0x1d, 0x51, 0x78, 0xf1, 0x38, 0xf8, 0x7f };
        const string clearText = "Two One Nine Two";
        var textBytes = Encoding.ASCII.GetBytes(clearText);

        const string key = "Thats my Kung Fuaaaaaaaabbbbbbbb";
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