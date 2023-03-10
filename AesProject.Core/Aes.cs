using AesProject.Core.Exceptions;

namespace AesProject.Core;

public class Aes
{
    private byte[] _data;
    private readonly AesKeySchedule _aesKeySchedule;
    private readonly List<AesBlock> _blocks = new();

    public Aes(byte[] data, byte[] key)
    {
        _data = data;
        _aesKeySchedule = new AesKeySchedule(key);
    }

    public byte[] Encrypt()
    {
        AddPadding();
        DivideIntoBlocks();
        var stream = new MemoryStream();
        foreach (var block in _blocks)
        {
            stream.Write(block.Encrypt());
        }

        return stream.ToArray();
    }

    public byte[] Decrypt()
    {
        DivideIntoBlocks();
        var stream = new MemoryStream();
        foreach (var block in _blocks)
        {
            stream.Write(block.Decrypt());
        }

        return RemovePadding(stream.ToArray());
    }

    private void AddPadding()
    {
        var stream = new MemoryStream();
        stream.Write(_data);
        var size = _data.Length;
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

        _data = stream.ToArray();
    }

    private void DivideIntoBlocks()
    {
        for (var i = 0; i < _data.Length / 16; i++)
        {
            var startIdx = i * 16;
            var endIdx = startIdx + 16;
            var block = _data[startIdx..endIdx];
            var aesBlock = new AesBlock(block, _aesKeySchedule);
            _blocks.Add(aesBlock);
        }
    }

    private byte[] RemovePadding(byte[] input)
    {
        var lastByte = input[^1];
        return input[..^lastByte];
    }


    public static byte[] Aes128Encrypt(byte[] data, byte[] key)
    {
        if (key.Length != 16)
        {
            throw new InvalidKeyLenghtException(16, key.Length);
        }

        var aes = new Aes(data, key);
        return aes.Encrypt();
    }

    public static byte[] Aes128Decrypt(byte[] data, byte[] key)
    {
        if (key.Length != 16)
        {
            throw new InvalidKeyLenghtException(16, key.Length);
        }

        var aes = new Aes(data, key);
        return aes.Decrypt();
    }

    public static byte[] Aes192Encrypt(byte[] data, byte[] key)
    {
        if (key.Length != 24)
        {
            throw new InvalidKeyLenghtException(24, key.Length);
        }

        var aes = new Aes(data, key);
        return aes.Encrypt();
    }
    
    public static byte[] Aes192Decrypt(byte[] data, byte[] key)
    {
        if (key.Length != 24)
        {
            throw new InvalidKeyLenghtException(24, key.Length);
        }

        var aes = new Aes(data, key);
        return aes.Decrypt();
    }
    
    public static byte[] Aes256Encrypt(byte[] data, byte[] key)
    {
        if (key.Length != 32)
        {
            throw new InvalidKeyLenghtException(32, key.Length);
        }

        var aes = new Aes(data, key);
        return aes.Encrypt();
    }
    
    public static byte[] Aes256Decrypt(byte[] data, byte[] key)
    {
        if (key.Length != 32)
        {
            throw new InvalidKeyLenghtException(32, key.Length);
        }

        var aes = new Aes(data, key);
        return aes.Decrypt();
    }
}