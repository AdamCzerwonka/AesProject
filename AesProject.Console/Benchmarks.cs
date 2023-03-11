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