using AesProject.Core.Exceptions;

namespace AesProject.Core;

public class AesBlock
{
    private readonly byte[,] _stateArray;
    private readonly AesKeySchedule _aesKeySchedule;
    private readonly int _roundsNumber;

    public AesBlock(byte[] input, AesKeySchedule keySchedule)
    {
        if (input.Length != 16)
        {
            throw new InvalidBlockSizeException(input.Length);
        }

        _aesKeySchedule = keySchedule;
        _roundsNumber = _aesKeySchedule.EncryptionRounds;
        _stateArray = ConvertToStateArray(input);
    }

    public byte[] Decrypt()
    {
        AddRoundKey(_aesKeySchedule.GetKey(_roundsNumber));
        for (var i = _roundsNumber - 1; i > 0; i--)
        {
            InvShiftRows();
            InvSubBytes();
            AddRoundKey(_aesKeySchedule.GetKey(i));
            InvMixColumns();
        }

        InvShiftRows();
        InvSubBytes();
        AddRoundKey(_aesKeySchedule.GetKey(0));
        
        return FlattenStateArray();
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

    private void InvSubBytes()
    {
        for (var i = 0; i < 4; i++)
        {
            for (var j = 0; j < 4; j++)
            {
                _stateArray[i, j] = SBox.GetInv(_stateArray[i, j]);
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

    private void InvShiftRows()
    {
        var matrix = (_stateArray.Clone() as byte[,])!;
        for (var i = 1; i < 4; i++)
        {
            for (var j = 0; j < 4; j++)
            {
                _stateArray[i, (j + i) % 4] = matrix[i, j];
            }
        }
    }

    private void MixColumns()
    {
        var matrix = (_stateArray.Clone() as byte[,])!;
        for (var i = 0; i < 4; i++)
        {
            _stateArray[0, i] = (byte)(MultiplyBy2(matrix[0, i]) ^ MultiplyBy3(matrix[1, i]) ^ matrix[2, i] ^
                                       matrix[3, i]);
            _stateArray[1, i] = (byte)(matrix[0, i] ^ MultiplyBy2(matrix[1, i]) ^ MultiplyBy3(matrix[2, i]) ^
                                       matrix[3, i]);
            _stateArray[2, i] = (byte)(matrix[0, i] ^ matrix[1, i] ^ MultiplyBy2(matrix[2, i]) ^
                                       MultiplyBy3(matrix[3, i]));
            _stateArray[3, i] = (byte)(MultiplyBy3(matrix[0, i]) ^ matrix[1, i] ^ matrix[2, i] ^
                                       MultiplyBy2(matrix[3, i]));
        }
    }

    private void InvMixColumns()
    {
        var matrix = (_stateArray.Clone() as byte[,])!;
        for (var i = 0; i < 4; i++)
        {
            _stateArray[0, i] =
                (byte)(
                    MultiplyBy14(matrix[0, i]) ^
                    MultiplyBy11(matrix[1, i]) ^
                    MultiplyBy13(matrix[2, i]) ^
                    MultiplyBy9(matrix[3, i])
                );
            _stateArray[1, i] =
                (byte)(
                    MultiplyBy9(matrix[0, i]) ^
                    MultiplyBy14(matrix[1, i]) ^
                    MultiplyBy11(matrix[2, i]) ^
                    MultiplyBy13(matrix[3, i])
                );
            _stateArray[2, i] =
                (byte)(
                    MultiplyBy13(matrix[0, i]) ^
                    MultiplyBy9(matrix[1, i]) ^
                    MultiplyBy14(matrix[2, i]) ^
                    MultiplyBy11(matrix[3, i])
                );
            _stateArray[3, i] =
                (byte)(
                    MultiplyBy11(matrix[0, i]) ^
                    MultiplyBy13(matrix[1, i]) ^
                    MultiplyBy9(matrix[2, i]) ^
                    MultiplyBy14(matrix[3, i])
                );
        }
    }

    private byte[] FlattenStateArray()
    {
        var res = new byte[16];
        for (var i = 0; i < 4; i++)
        {
            for (var j = 0; j < 4; j++)
            {
                res[i * 4 + j] = _stateArray[j, i];
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

    private static byte MultiplyBy2(byte a)
    {
        var value = a << 1;
        if ((a & (1 << 7)) != 0)
        {
            value ^= 0x1B;
        }

        return (byte)value;
    }

    private static byte MultiplyBy3(byte a)
    {
        return (byte)(MultiplyBy2(a) ^ a);
    }

    private static byte MultiplyBy9(byte a)
    {
        var inner = MultiplyBy2(a);
        var inner2 = MultiplyBy2(inner);
        var inner3 = MultiplyBy2(inner2);
        var result = inner3 ^ a;
        return (byte)(result);
    }

    private static byte MultiplyBy11(byte a)
    {
        var inner = MultiplyBy2(a);
        var inner2 = MultiplyBy2(inner);
        var inner3 = (byte)(inner2 ^ a);
        var inner4 = MultiplyBy2(inner3);
        var result = (byte)(inner4 ^ a);
        return result;
    }

    private static byte MultiplyBy13(byte a)
    {
        var inner = MultiplyBy2(a);
        var inner2 = (byte)(inner ^ a);
        var inner3 = MultiplyBy2(inner2);
        var inner4 = MultiplyBy2(inner3);
        var result = inner4 ^ a;
        return (byte)result;
    }

    private static byte MultiplyBy14(byte a)
    {
        var inner = MultiplyBy2(a);
        var inner2 = (byte)(inner ^ a);
        var inner3 = MultiplyBy2(inner2);
        var inner4 = (byte)(inner3 ^ a);
        var result = MultiplyBy2(inner4);
        return result;
    }
}