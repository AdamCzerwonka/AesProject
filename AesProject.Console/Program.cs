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

using AesProject.Console;
using AesProject.Core;
using BenchmarkDotNet.Running;

// BenchmarkRunner.Run<Benchmarks>();

var key = new AesKeySchedule(Array.Empty<byte>());

// var keyBytes = "Thats my Kung Fu"u8.ToArray();
// var aes = new Aes(new byte[1], keyBytes);
// var result = aes.Encrypt(@"C:\Users\macze\Downloads\zad1.zip");
// using var outputFile = File.OpenWrite("test.enc");
// outputFile.Write(result);