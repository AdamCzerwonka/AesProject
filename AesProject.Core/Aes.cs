using AesProject.Core.Exceptions;

namespace AesProject.Core;

public class Aes
{
    private readonly byte[] _key;

    public Aes(byte[] input, byte[] key)
    {
        var inputSize = input.Length;
        var numberOfBlocks = inputSize / 16;
        if (numberOfBlocks * 16 < inputSize)
        {
            numberOfBlocks++;
        }

        BlockNumber = numberOfBlocks;
        _input = input;
        _key = key;
    }

    public byte[] Encrypt()
    {
        AddPadding();
        DivideIntoBlocks();
        var stream = new MemoryStream();
        foreach (var t in Blocks)
        {
            var block = new AesBlock(t, _key);
            var result = block.Encrypt();
            stream.Write(result);
        }

        return stream.ToArray();
    }

    public byte[] Decrypt()
    {
        DivideIntoBlocks();
        var stream = new MemoryStream();
        foreach (var t in Blocks)
        {
            var block = new AesBlock(t, _key);
            var result = block.Decrypt();
            stream.Write(result);
        }


        return RemovePadding(stream.ToArray());
    }

    private void AddPadding()
    {
        var stream = new MemoryStream();
        stream.Write(_input);
        var size = _input.Length;
        if (size % 16 == 0)
        {
            var buff = new byte[16];
            for (var i = 0; i < 16; i++)
            {
                buff[i] = 16;
            }

            stream.Write(buff);
        }
        else
        {
            var toAdd = 16 - (size % 16);
            var buff = new byte[toAdd];
            for (var i = 0; i < toAdd; i++)
            {
                buff[i] = (byte)toAdd;
            }

            stream.Write(buff);
        }

        _input = stream.ToArray();
    }

    private void DivideIntoBlocks()
    {
        for (var i = 0; i < _input.Length / 16; i++)
        {
            var startIdx = i * 16;
            var endIdx = startIdx + 16;
            var block = _input[startIdx..endIdx];
            Blocks.Add(block);
        }
    }

    private byte[] RemovePadding(byte[] input)
    {
        var lastByte = input[^1];
        return input[..^lastByte];
    }

    public int BlockNumber { get; set; }
    private byte[] _input;
    public List<byte[]> Blocks { get; set; } = new();

    public static byte[] Aes128Encrypt(byte[] data, byte[] key)
    {
        if (key.Length != 16)
        {
            throw new InvalidKeyLenghtException(16, key.Length);
        }

        var aes = new Aes(data, key);
        return aes.Encrypt();
    }
}