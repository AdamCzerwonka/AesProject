#region copy
// Aes implementation in C#
// Copyright (C) 2023 Adam Czerwonka, Marcel Badek
// 
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
#endregion

using System.Text;

namespace AesProject.Core.Tests;

public class AesTests
{
    [Fact]
    public void TestAes_ShouldAddOneBlockOfPadding_WhenGivenInputWithBlockSize()
    {
        var expected = new byte[]
        {
            0x29, 0xC3, 0x50, 0x5F, 0x57, 0x14, 0x20, 0xF6, 0x40, 0x22, 0x99, 0xB3, 0x1A, 0x02, 0xD7, 0x3A, 0xB3, 0xE4,
            0x6F, 0x11, 0xBA, 0x8D, 0x2B, 0x97, 0xC1, 0x87, 0x69, 0x44, 0x9A, 0x89, 0xE8, 0x68
        };
        var toEncrypt = "Two One Nine Two";
        var key = "Thats my Kung Fu";

        var aes = new Aes(Encoding.ASCII.GetBytes(key));
        var result = aes.Encrypt(Encoding.ASCII.GetBytes(toEncrypt));

        Assert.Equal(expected, result);
    }


    [Fact]
    public void TestAes_ShouldAddCorrectPadding_WhenGivenInputLongerThanBlockSize()
    {
        var expected = new byte[]
        {
            0x29, 0xc3, 0x50, 0x5f, 0x57, 0x14, 0x20, 0xf6, 0x40, 0x22, 0x99, 0xb3, 0x1a, 0x02, 0xd7, 0x3a, 0x94, 0xe2,
            0xa9, 0x4d, 0xea, 0xc0, 0x20, 0x0e, 0x3a, 0x67, 0x8e, 0x7f, 0xf7, 0xf0, 0x96, 0x25
        };
        var toEncrypt = "Two One Nine Twoa";
        var key = "Thats my Kung Fu";

        var aes = new Aes(Encoding.ASCII.GetBytes(key));
        var result = aes.Encrypt(Encoding.ASCII.GetBytes(toEncrypt));

        Assert.Equal(expected, result);
    }

    [Fact]
    public void TestDecrypt_ShouldReturnInputBytes_WhenGivenEncypptedInput()
    {
        var testText = "TestText"u8.ToArray();
        var testKey = "aaaaaaaaaaaaaaaa"u8.ToArray();

        var encryptedText = Aes.Aes128Encrypt(testText, testKey);

        var result = new Aes(testKey).Decrypt(encryptedText);
        Assert.Equal(testText, result);
    }

    [Fact]
    public void TestEncryptDecrypt128_ShouldReturnSameValueAsInput_WhenGivenEncryptedInput()
    {
        var testText = "Test Text"u8.ToArray();
        var testKey = "aaaaaaaaaaaaaaaa"u8.ToArray();

        var encryptedText = Aes.Aes128Encrypt(testText, testKey);
        var result = Aes.Aes128Decrypt(encryptedText, testKey);

        Assert.Equal(testText, result);
    }

    [Fact]
    public void TestEncryptDecrypt192_ShouldReturnSameValueAsInput_WhenGivenEncryptedInput()
    {
        var testText = "Test Text"u8.ToArray();
        var testKey = "aaaaaaaaaaaaaaaaaaaaaaaa"u8.ToArray();

        var encryptedText = Aes.Aes192Encrypt(testText, testKey);
        var result = Aes.Aes192Decrypt(encryptedText, testKey);

        Assert.Equal(testText, result);
    }

    [Fact]
    public void TestEncryptDecrypt256_ShouldReturnSameValueAsInput_WhenGivenEncryptedInput()
    {
        var testText = "Test Text"u8.ToArray();
        var testKey = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"u8.ToArray();

        var encryptedText = Aes.Aes256Encrypt(testText, testKey);
        var result = Aes.Aes256Decrypt(encryptedText, testKey);

        Assert.Equal(testText, result);
    }
}