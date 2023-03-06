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
        AddPadding();
        DivideIntoBlocks();
    }

    public byte[] Encrypt()
    {
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
        var stream = new MemoryStream();
        foreach (var t in Blocks)
        {
            var block = new AesBlock(t, _key);
            var result = block.Decrypt();
            stream.Write(result);
        }

        return stream.ToArray();
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

    public int BlockNumber { get; set; }
    private byte[] _input;
    public List<byte[]> Blocks { get; set; } = new();
}