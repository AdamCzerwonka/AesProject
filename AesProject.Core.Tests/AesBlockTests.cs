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
using AesProject.Core.Exceptions;

namespace AesProject.Core.Tests;

public class AesBlockTests
{
    private readonly byte[] _bytes = "Two One Nine Two"u8.ToArray();

    [Fact]
    public void TestEncrypt_ShouldCorrectlyEncryptBlock_WhenGiven128BitKeyCorrectInput()
    {
        byte[] expectedResult =
            { 0x29, 0xc3, 0x50, 0x5F, 0x57, 0x14, 0x20, 0xF6, 0x40, 0x22, 0x99, 0xB3, 0x1A, 0x02, 0xD7, 0x3A };

        const string key = "Thats my Kung Fu";
        var keyBytes = Encoding.ASCII.GetBytes(key);
        var keySchedule = new AesKeySchedule(keyBytes);

        var block = new AesBlock(_bytes, keySchedule);
        var result = new byte[16];
        block.Encrypt(result);

        Assert.Equal(expectedResult, result);
    }

    [Fact]
    public void TestEncrypt_ShouldCorrectlyEncryptBlock_WhenGiven192BitKeyCorrectInput()
    {
        byte[] expectedResult =
            { 0x83, 0xd0, 0x7d, 0xb6, 0x15, 0xda, 0x00, 0xa8, 0xb2, 0xd4, 0x61, 0xd6, 0x00, 0x4a, 0xf8, 0xcb };

        const string key = "Thats my Kung Fuaaaaaaaa";
        var keyBytes = Encoding.ASCII.GetBytes(key);
        var keySchedule = new AesKeySchedule(keyBytes);

        var block = new AesBlock(_bytes, keySchedule);
        var result = new byte[16];
        block.Encrypt(result);

        Assert.Equal(expectedResult, result);
    }

    [Fact]
    public void TestEncrypt_ShouldCorrectlyEncryptBlock_WhenGiven256BitKeyCorrectInput()
    {
        byte[] expectedResult =
            { 0x39, 0x8d, 0xff, 0x4e, 0x8b, 0xd9, 0xba, 0x23, 0x35, 0x1d, 0x51, 0x78, 0xf1, 0x38, 0xf8, 0x7f };

        const string key = "Thats my Kung Fuaaaaaaaabbbbbbbb";
        var keyBytes = Encoding.ASCII.GetBytes(key);
        var keySchedule = new AesKeySchedule(keyBytes);

        var block = new AesBlock(_bytes, keySchedule);
        var result = new byte[16];
         block.Encrypt(result);

        Assert.Equal(expectedResult, result);
    }

    [Theory]
    [InlineData(new byte[0])]
    [InlineData(new byte[] { 0x00 })]
    public void TestAesBlock_ShouldThrow_WhenGivenIncorrectBlockSize(byte[] input)
    {
        var keySchedule = new AesKeySchedule(new byte[16]);
        Assert.Throws<InvalidBlockSizeException>(() => new AesBlock(input, keySchedule));
    }
}