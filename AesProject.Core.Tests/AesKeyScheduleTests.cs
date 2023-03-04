using AesProject.Core.Exceptions;
using AesProject.Core.Tests.TestData;

namespace AesProject.Core.Tests;

public class AesKeyScheduleTests
{
    [Theory]
    [ClassData(typeof(InvalidLenghtKeys))]
    public void TestConstructor_ShouldThrow_WhenGivenIncorrectKeyLenght(byte[] key)
    {
        Assert.Throws<InvalidKeyLenghtException>(() => new AesKeySchedule(key, 10));
    }

    [Theory]
    [ClassData(typeof(Correct128BitKeys))]
    public void TestAesKeySchedule_ShouldGenerateCorrectKeys_WhenGiven128BitKey(byte[] key, byte[] lastExpandedKey)
    {
        const int lastRoundNumber = 10;
        var aesKeySchedule = new AesKeySchedule(key, lastRoundNumber);
        Assert.Equal(lastExpandedKey, aesKeySchedule.GetKey(lastRoundNumber));
    }
}