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
        var inputBuffer = new byte[16];
        var outputBuffer = new byte[16];
        var block = new AesBlock(inputBuffer, _aesKeySchedule);
        for (var i = 0; i < _data.Length / 16; i++)
        {
            var startIdx = i * 16;
            Buffer.BlockCopy(_data, startIdx, inputBuffer, 0, 16);
            block.Encrypt(inputBuffer, outputBuffer);
            Buffer.BlockCopy(outputBuffer, 0, _data, startIdx, 16);
        }

        return _data;
    }

    public byte[] Decrypt()
    {
        DivideIntoBlocks();
        var stream = new MemoryStream();
        var buffer = new byte[16];
        foreach (var block in _blocks)
        {
            block.Decrypt(buffer);
            stream.Write(buffer);
        }

        return RemovePadding(stream.ToArray());
    }

    private void AddPadding()
    {
        var size = _data.Length;
        int toAppend;
        byte[] buffer;
        if (size % 16 == 0)
        {
            toAppend = 16;
            buffer = new byte[toAppend];
            for (var i = 0; i < 16; i++)
            {
                buffer[i] = 16;
            }
        }
        else
        {
            toAppend = 16 - (size % 16);
            buffer = new byte[toAppend];
            for (var i = 0; i < toAppend; i++)
            {
                buffer[i] = (byte)toAppend;
            }
        }

        Array.Resize(ref _data, size + toAppend);
        Buffer.BlockCopy(buffer, 0,_data, size, toAppend);
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