using AesProject.Core.Exceptions;

namespace AesProject.Core;

public class AesKeySchedule
{
    public AesKeySchedule(byte[] key, int rounds)
    {
        if (key.Length != 16)
        {
            throw new InvalidKeyLenghtException(16, key.Length);
        }
        
        for (var i = 1; i <= rounds; i++)
        {
            key = GenerateNextKey(key,i);
            _keys.Add(key);
        }    
    }

    private readonly List<byte[]> _keys = new();

    public byte[] GetKey(int roundNumber)
        => _keys[roundNumber - 1];

    private byte[] GenerateNextKey(byte[] key, int round)
    {
        var nextKey = new byte[16];
        var w3 = key[12..];

        w3 = RotWord(w3);

        for (var i = 0; i < 4; i++)
        {
            w3[i] = SBox.Get(w3[i]);
        }

        w3[0] ^= _rcon[round - 1];

        for (var i = 0; i < 4; i++)
        {
            var startIdx = i * 4;
            var endIdx = startIdx + 4;
            var slice = key[startIdx..endIdx];
            for (var j = 0; j < 4; j++)
            {
                w3[j] ^= slice[j];
            }

            w3.CopyTo(nextKey, startIdx);
        }

        return nextKey;
    }

    private static byte[] RotWord(byte[] word)
    {
        var zeroElement = word[0];
        for (var i = 1; i < 4; i++)
        {
            word[i - 1] = word[i];
        }

        word[3] = zeroElement;
        return word;
    }

    private readonly byte[] _rcon =
    {
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
    };
}