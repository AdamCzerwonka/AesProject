// See https://aka.ms/new-console-template for more information

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