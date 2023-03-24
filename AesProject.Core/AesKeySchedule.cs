using AesProject.Core.Exceptions;

namespace AesProject.Core;

/// <summary>
/// This class expands aes encryption key
/// </summary>
public class AesKeySchedule
{
    private readonly byte[] _encryptionKey;

    /// <summary>
    /// Creates expanded key based on passed encryption key
    /// </summary>
    /// <param name="key">key bytes</param>
    /// <exception cref="InvalidKeyLenghtException">Throw when key lenght is not correct</exception>
    public AesKeySchedule(byte[] key)
    {
        if (key.Length is not (16 or 24 or 32))
        {
            throw new InvalidKeyLenghtException();
        }
        
        _encryptionKey = key;
        var expandedKey = ExpandKey();
        var rounds = EncryptionRounds + 1;
        for (var i = 0; i < rounds; i++)
        {
            var startIdx = i * 16;
            var slice = expandedKey[startIdx..(startIdx + 16)];
            _keys.Add(i, slice);
        }
    }


    /// <summary>
    /// Returns number of rounds based on provided key
    /// </summary>
    /// <exception cref="InvalidKeyLenghtException">Thrown when key length is invalid</exception>
    public int EncryptionRounds
        => _encryptionKey.Length switch
        {
            16 => 10,
            24 => 12,
            32 => 14,
            _ => throw new InvalidKeyLenghtException()
        };

    private readonly Dictionary<int, byte[]> _keys = new();

    /// <summary>
    /// Returns key for given round number
    /// </summary>
    /// <param name="roundNumber">round number</param>
    /// <returns></returns>
    public byte[] GetKey(int roundNumber)
        => _keys[roundNumber];

    private byte[] ExpandKey()
    {
        var keySize = _encryptionKey.Length;
        var expandedKeySize = (EncryptionRounds + 1) * 16;
        var expandedKey = new byte[expandedKeySize];
        _encryptionKey.CopyTo(expandedKey, 0);
        var byteCount = keySize;
        var round = 0;
        while (byteCount < expandedKeySize)
        {
            var temp = expandedKey[(byteCount - 4)..byteCount];
            if (byteCount % keySize == 0)
            {
                temp = RotWord(temp);
                for (var i = 0; i < 4; i++)
                {
                    temp[i] = SBox.Get(temp[i]);
                }

                temp[0] ^= Rcon[round++];
            }

            if (keySize == 32 && byteCount % 32 == 16)
            {
                for (var i = 0; i < 4; i++)
                {
                    temp[i] = SBox.Get(temp[i]);
                }
            }

            for (var j = 0; j < 4; j++)
            {
                expandedKey[byteCount] = (byte)(expandedKey[byteCount - keySize] ^ temp[j]);
                byteCount++;
            }
        }

        return expandedKey;
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

    private static readonly byte[] Rcon =
    {
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
    };
}