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

using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using Aes = AesProject.Core.Aes;

namespace AesProject.Console;

[MemoryDiagnoser]
public class Benchmarks
{
    [Params(1000, 100000, 1000000)]
    public int Size { get; set; }

    private byte[] _input = null!;
    private byte[] _key = null!;

    [GlobalSetup]
    public void Setup()
    {
        _input = RandomNumberGenerator.GetBytes(Size);
        _key = RandomNumberGenerator.GetBytes(16);
    }
    
    [Benchmark]
    public byte[] Encrypt()
    {
        var result = Aes.Aes128Encrypt(_input, _key);
        return result;
    }
    
}