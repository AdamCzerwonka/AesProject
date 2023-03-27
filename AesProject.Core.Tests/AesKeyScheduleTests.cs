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

using AesProject.Core.Exceptions;
using AesProject.Core.Tests.TestData;

namespace AesProject.Core.Tests;

public class AesKeyScheduleTests
{
    [Theory]
    [ClassData(typeof(InvalidLenghtKeys))]
    public void TestConstructor_ShouldThrow_WhenGivenIncorrectKeyLenght(byte[] key)
    {
        Assert.Throws<InvalidKeyLenghtException>(() => new AesKeySchedule(key));
    }

    [Theory]
    [ClassData(typeof(Correct128BitKeys))]
    public void TestAesKeySchedule_ShouldGenerateCorrectKeys_WhenGiven128BitKey(byte[] key, byte[] lastExpandedKey)
    {
        const int lastRoundNumber = 10;
        var aesKeySchedule = new AesKeySchedule(key);
        Assert.Equal(lastExpandedKey, aesKeySchedule.GetKey(lastRoundNumber));
    }
    
    [Theory]
    [ClassData(typeof(Correct192BitKeys))]
    public void TestAesKeySchedule_ShouldGenerateCorrectKeys_WhenGiven192BitKey(byte[] key, byte[] lastExpandedKey)
    {
        const int lastRoundNumber = 12;
        var aesKeySchedule = new AesKeySchedule(key);
        Assert.Equal(lastExpandedKey, aesKeySchedule.GetKey(lastRoundNumber));
    }
    
    [Theory]
    [ClassData(typeof(Correct256BitKeys))]
    public void TestAesKeySchedule_ShouldGenerateCorrectKeys_WhenGiven256BitKey(byte[] key, byte[] lastExpandedKey)
    {
        const int lastRoundNumber = 14;
        var aesKeySchedule = new AesKeySchedule(key);
        Assert.Equal(lastExpandedKey, aesKeySchedule.GetKey(lastRoundNumber));
    }
}