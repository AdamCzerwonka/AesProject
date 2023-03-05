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

    private void DivideIntoBlocks()
    {
        for (var i = 0; i < BlockNumber; i++)
        {
            var startIdx = i * 16;
            var endIdx = startIdx + 16;
            if (endIdx > _input.Length)
            {
                endIdx = _input.Length;
            }

            var block = _input[startIdx..endIdx];
            Blocks.Add(block);
        }

        var lastBlock = Blocks.Last();
        if (lastBlock.Length < 16)
        {
            var lastBlockSize = lastBlock.Length;
            var paddedLastBlock = new byte[16];
            lastBlock.CopyTo(paddedLastBlock, 0);
            for (var i = lastBlockSize; i < 16; i++)
            {
                paddedLastBlock[i] = (byte)(16 - lastBlockSize);
            }

            Blocks[BlockNumber - 1] = paddedLastBlock;
        }
        else
        {
            var paddingBlock = new byte[16];
            for (var i = 0; i < 16; i++)
            {
                paddingBlock[i] = 16;
            }

            Blocks.Add(paddingBlock);
        }
    }

    public int BlockNumber { get; set; }
    private readonly byte[] _input;
    public List<byte[]> Blocks { get; set; } = new();
}