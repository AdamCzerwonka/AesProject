using AesProject.Core.Exceptions;

namespace AesProject.Core;

public class AesBlock
{
    private readonly byte[,] _stateArray;
    private readonly AesKeySchedule _aesKeySchedule;
    private readonly int _roundsNumber;
    
    public AesBlock(byte[] input, byte[] key)
    {
        if (input.Length != 16)
        {
            throw new InvalidBlockSizeException(input.Length);
        }

        _roundsNumber = key.Length switch
        {
            16 => 10,
            24 => 12,
            32 => 14,
            _ => throw new ArgumentException("Key size not good")
        };
        
        _aesKeySchedule = new AesKeySchedule(key);
        _stateArray = ConvertToStateArray(input);
    }

    public byte[] Encrypt()
    {
        AddRoundKey(_aesKeySchedule.GetKey(0));
        for (var i = 1; i < _roundsNumber; i++)
        {
            SubBytes();
            ShiftRows();
            MixColumns();
            AddRoundKey(_aesKeySchedule.GetKey(i));
        }
        SubBytes();
        ShiftRows();
        AddRoundKey(_aesKeySchedule.GetKey(_roundsNumber));

        return FlattenStateArray();
    }

    private void AddRoundKey(byte[] key)
    {
        var keyStateArray = ConvertToStateArray(key);
        for (var i = 0; i < 4; i++)
        {
            for (var j = 0; j < 4; j++)
            {
                _stateArray[i, j] ^= keyStateArray[i, j];
            }
        }
    }

    private void SubBytes()
    {
        for (var i = 0; i < 4; i++)
        {
            for (var j = 0; j < 4; j++)
            {
                _stateArray[i, j] = SBox.Get(_stateArray[i, j]);
            }
        }
    }

    private void ShiftRows()
    {
        var matrix = (_stateArray.Clone() as byte[,])!;
        for (var i = 1; i < 4; i++)
        {
            for (var j = 0; j < 4; j++)
            {
                _stateArray[i, j] = matrix[i, (j + i) % 4];
            }
        }
    }

    private void MixColumns()
    {
        var matrix = (_stateArray.Clone() as byte[,])!;
        for (var i = 0; i < 4; i++)
        {
            _stateArray[0, i] = (byte)(MultipleBy2(matrix[0, i]) ^ MultipleBy3(matrix[1, i]) ^ matrix[2, i] ^
                                       matrix[3, i]);
            _stateArray[1, i] = (byte)(matrix[0, i] ^ MultipleBy2(matrix[1, i]) ^ MultipleBy3(matrix[2, i]) ^
                                       matrix[3, i]);
            _stateArray[2, i] = (byte)(matrix[0, i] ^ matrix[1, i] ^ MultipleBy2(matrix[2, i]) ^
                                       MultipleBy3(matrix[3, i]));
            _stateArray[3, i] = (byte)(MultipleBy3(matrix[0, i]) ^ matrix[1, i] ^ matrix[2, i] ^
                                       MultipleBy2(matrix[3, i]));
        }
    }
    
    private byte[] FlattenStateArray()
    {
        var res = new byte[16];
        for (var i = 0; i < 4; i++)
        {
            for (var j = 0; j < 4; j++)
            {
                res[i * 4 + j] = _stateArray[j,i];
            }
        }
        return res;
    }
    
    private static byte[,] ConvertToStateArray(byte[] bytes)
    {
        var matrix = new byte[4, 4];
        for (var i = 0; i < 4; i++)
        {
            for (var j = 0; j < 4; j++)
            {
                matrix[i, j] = bytes[i + j * 4];
            }
        }

        return matrix;
    }

    private static byte MultipleBy2(byte a)
    {
        var value = a << 1;
        if ((a & (1 << 7)) != 0)
        {
            value ^= 0x1B;
        }

        return (byte)value;
    }

    private static byte MultipleBy3(byte a)
    {
        return (byte)(MultipleBy2(a) ^ a);
    }

}