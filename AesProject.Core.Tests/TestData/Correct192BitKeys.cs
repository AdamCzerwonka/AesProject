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

public class Correct192BitKeys : IEnumerable<object[]>
{
    public IEnumerator<object[]> GetEnumerator()
    {
        yield return new object[]
        {
            new byte[24],
            new byte[]
            {
                0x43, 0x2a, 0xc8, 0x86, 0xd8, 0x34, 0xc0, 0xb6, 0xd2, 0xc7, 0xdf, 0x11, 0x98, 0x4c, 0x59, 0x70
            }
        };
        yield return new object[]
        {
            new byte[]
            {
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
            },
            new byte[]
            {
                0x59, 0x8e, 0x48, 0x2f, 0xff, 0xae, 0xe3, 0x64, 0x3a, 0x98, 0x9a, 0xcd, 0x13, 0x30, 0xb4, 0x18
            }
        };
    }

    IEnumerator IEnumerable.GetEnumerator()
    {
        return GetEnumerator();
    }
}