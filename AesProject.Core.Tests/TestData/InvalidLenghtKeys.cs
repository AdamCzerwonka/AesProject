using System.Collections;

namespace AesProject.Core.Tests.TestData;

public class InvalidLenghtKeys : IEnumerable<object[]>
{
    public IEnumerator<object[]> GetEnumerator()
    {
        yield return new object[] { new byte[] { 0x10, 0x10, 0x01 } };
        yield return new object[]
        {
            new byte[]
            {
                0x10, 0x10, 0x01, 0x10, 0x10, 0x01, 0x10, 0x10, 0x01, 0x10, 0x10, 0x01, 0x10, 0x10, 0x01, 0x01, 0x01,
                0x01
            }
        };
        yield return new object[] { Array.Empty<byte>() };
    }

    IEnumerator IEnumerable.GetEnumerator()
    {
        return GetEnumerator();
    }
}