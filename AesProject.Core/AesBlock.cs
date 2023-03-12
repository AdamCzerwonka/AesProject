﻿using AesProject.Core.Exceptions;

namespace AesProject.Core;

public class AesBlock
{
    private readonly byte[,] _stateArray = new byte[4, 4];
    private readonly byte[,] _keyStateArray = new byte[4, 4];
    private readonly AesKeySchedule _aesKeySchedule;
    private int _roundsNumber;
    private readonly byte[,] _buffer = new byte[4, 4];

    public AesBlock(byte[] input, AesKeySchedule keySchedule)
    {
        if (input.Length != 16)
        {
            throw new InvalidBlockSizeException(input.Length);
        }

        _aesKeySchedule = keySchedule;
        _roundsNumber = _aesKeySchedule.EncryptionRounds;
        ConvertToStateArray(input, _stateArray);
    }

    public void Decrypt(byte[] output)
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

        FlattenStateArray(output);
    }

    public void Encrypt(byte[] input, byte[] output)
    {
        if (input.Length != 16)
        {
            throw new InvalidBlockSizeException(input.Length);
        }

        _roundsNumber = _aesKeySchedule.EncryptionRounds;
        ConvertToStateArray(input, _stateArray);
        Encrypt(output);
    }

    public void Encrypt(byte[] output)
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

        FlattenStateArray(output);
    }

    private void AddRoundKey(byte[] key)
    {
        ConvertToStateArray(key, _keyStateArray);
        for (var i = 0; i < 4; i++)
        {
            for (var j = 0; j < 4; j++)
            {
                _stateArray[i, j] ^= _keyStateArray[i, j];
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
        // var matrix = (_stateArray.Clone() as byte[,])!;
        Array.Copy(_stateArray, _buffer, _buffer.Length);
        // Buffer.BlockCopy(_stateArray,0,_buffer,0, _buffer.Length);

        for (var i = 1; i < 4; i++)
        {
            for (var j = 0; j < 4; j++)
            {
                _stateArray[i, j] = _buffer[i, (j + i) % 4];
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
        // var matrix = (_stateArray.Clone() as byte[,])!;
        // Buffer.BlockCopy(_stateArray,0,_buffer,0, _buffer.Length);
        Array.Copy(_stateArray, _buffer, _buffer.Length);

        for (var i = 0; i < 4; i++)
        {
            _stateArray[0, i] = (byte)(MultiplyBy2(_buffer[0, i]) ^ MultiplyBy3(_buffer[1, i]) ^ _buffer[2, i] ^
                                       _buffer[3, i]);
            _stateArray[1, i] = (byte)(_buffer[0, i] ^ MultiplyBy2(_buffer[1, i]) ^ MultiplyBy3(_buffer[2, i]) ^
                                       _buffer[3, i]);
            _stateArray[2, i] = (byte)(_buffer[0, i] ^ _buffer[1, i] ^ MultiplyBy2(_buffer[2, i]) ^
                                       MultiplyBy3(_buffer[3, i]));
            _stateArray[3, i] = (byte)(MultiplyBy3(_buffer[0, i]) ^ _buffer[1, i] ^ _buffer[2, i] ^
                                       MultiplyBy2(_buffer[3, i]));
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

    private void FlattenStateArray(byte[] res)
    {
        for (var i = 0; i < 4; i++)
        {
            for (var j = 0; j < 4; j++)
            {
                res[i * 4 + j] = _stateArray[j, i];
            }
        }
    }

    private static void ConvertToStateArray(byte[] bytes, byte[,] matrix)
    {
        for (var i = 0; i < 4; i++)
        {
            for (var j = 0; j < 4; j++)
            {
                matrix[i, j] = bytes[i + j * 4];
            }
        }
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