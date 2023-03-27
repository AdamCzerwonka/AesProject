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