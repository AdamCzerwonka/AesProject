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

public class Correct256BitKeys : IEnumerable<object[]>
{
    public IEnumerator<object[]> GetEnumerator()
    {
        yield return new object[]
        {
            new byte[32],
            new byte[]
            {
                0x10, 0xf8, 0x0a, 0x17, 0x53, 0xbf, 0x72, 0x9c, 0x45, 0xc9, 0x79, 0xe7, 0xcb, 0x70, 0x63, 0x85
            }
        };
        yield return new object[]
        {
            new byte[]
            {
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff
            },
            new byte[]
            {
                0x54, 0x6d, 0x42, 0x4f, 0x27, 0xde, 0x1e, 0x80, 0x88, 0x40, 0x2b, 0x5b, 0x4d, 0xae, 0x35, 0x5e
            }
        };
    }

    IEnumerator IEnumerable.GetEnumerator()
    {
        return GetEnumerator();
    }
}