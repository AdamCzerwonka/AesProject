using AesProject.Core.Exceptions;

namespace AesProject.Core;

public class AesKeySchedule
{
    public AesKeySchedule(byte[] key)
    {
        if (key.Length == 16)
        {
            _keys.Add(0, key);
            for (var i = 1; i <= 10; i++)
            {
                key = Generate128NextKey(key, i);
                _keys.Add(i, key);
            }
        }
        else if (key.Length == 24)
        {
            var test = Generate192NextKey(key);
            for (var i = 0; i < 13; i++)
            {
                var startIdx = i * 16;
                var slice = test[startIdx..(startIdx + 16)];
                _keys.Add(i, slice);
            }
        }
        else if (key.Length == 32)
        {
            // 256 Key Exp
        }
        else
        {
            throw new InvalidKeyLenghtException(16, key.Length);
        }
    }

    private readonly Dictionary<int, byte[]> _keys = new();

    public byte[] GetKey(int roundNumber)
        => _keys[roundNumber];

    private byte[] Generate192NextKey(byte[] key)
    {
        var expandedKey = new byte[208];
        key.CopyTo(expandedKey, 0);
        var byteCount = 24;
        var round = 0;
        while (byteCount < 208)
        {
            var xorBytes = expandedKey[(byteCount - 4)..byteCount];
            if (byteCount % 24 == 0)
            {
                xorBytes = RotWord(xorBytes);
                for (var i = 0; i < 4; i++)
                {
                    xorBytes[i] = SBox.Get(xorBytes[i]);
                }

                xorBytes[0] ^= _rcon[round++];
            }

            for (var j = 0; j < 4; j++)
            {
                expandedKey[byteCount] = (byte)(expandedKey[byteCount - 24] ^ xorBytes[j]);
                byteCount++;
            }
        }

        return expandedKey;
    }

    private byte[] Generate128NextKey(byte[] key, int round)
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