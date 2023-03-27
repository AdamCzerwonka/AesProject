#region copy
// Aes implementation in C#
// Copyright (C) 2023 Adam Czerwonka, Marcel Badek
// 
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
#endregion

using AesProject.Core.Exceptions;

namespace AesProject.Core;

/// <summary>
/// Class is responsible of encrypting and decrypting data using aes algorithm
/// </summary>
public class Aes
{
    private byte[] _data = null!;
    private readonly AesBlock _block;

    /// <summary>
    /// Creates new aes object and initializes key schedule
    /// </summary>
    /// <param name="key">Encryption key</param>
    public Aes(byte[] key)
    {
        var aesKeySchedule = new AesKeySchedule(key);
        _block = new AesBlock(aesKeySchedule);
    }

    /// <summary>
    /// Encrypts given data
    /// </summary>
    /// <param name="data">Data for encryption</param>
    /// <returns>Encrypted data</returns>
    public byte[] Encrypt(byte[] data)
    {
        _data = data;
        AddPadding();
        var inputBuffer = new byte[16];
        var outputBuffer = new byte[16];
        for (var i = 0; i < _data.Length / 16; i++)
        {
            var startIdx = i * 16;
            Buffer.BlockCopy(_data, startIdx, inputBuffer, 0, 16);
            _block.Encrypt(inputBuffer, outputBuffer);
            Buffer.BlockCopy(outputBuffer, 0, _data, startIdx, 16);
        }

        return _data;
    }

    /// <summary>
    /// Encrypts data from provided file
    /// </summary>
    /// <param name="fileName">name of the file to read data from</param>
    /// <returns>encrypted data</returns>
    public byte[] Encrypt(string fileName)
    {
        var info = new FileInfo(fileName);
        using var file = File.OpenRead(fileName);
        var outputStream = new MemoryStream((int)info.Length + 16);
        var buffer = new byte[16];
        var outputBuffer = new byte[16];
        int bytesRead;
        while ((bytesRead = file.Read(buffer)) != 0)
        {
            if (bytesRead == 16)
            {
                _block.Encrypt(buffer, outputBuffer);
            }
            else
            {
                var bytesToAdd = 16 - bytesRead;
                for (var i = bytesRead; i < 16; i++)
                {
                    buffer[i] = (byte)bytesToAdd;
                }

                _block.Encrypt(buffer, outputBuffer);
            }

            outputStream.Write(outputBuffer);
        }

        // ReSharper disable once InvertIf
        if (info.Length % 16 == 0)
        {
            for (var i = 0; i < 16; i++)
            {
                buffer[i] = 16;
            }

            _block.Encrypt(buffer, outputBuffer);
            outputStream.Write(outputBuffer);
        }

        return outputStream.ToArray();
    }

    public byte[] Decrypt(string fileName)
    {
        var info = new FileInfo(fileName);
        using var file = File.OpenRead(fileName);
        var outputStream = new MemoryStream((int)info.Length + 16);
        var buffer = new byte[16];
        var outputBuffer = new byte[16];
        while (file.Read(buffer) != 0)
        {
            _block.Decrypt(buffer, outputBuffer);
            outputStream.Write(outputBuffer);
        }

        return RemovePadding(outputStream.ToArray());
    }

    /// <summary>
    /// Decrypt given data
    /// </summary>
    /// <param name="data">data to be decrypted</param>
    /// <returns>decrypted data</returns>
    public byte[] Decrypt(byte[] data)
    {
        _data = data;

        var inputBuffer = new byte[16];
        var outputBuffer = new byte[16];
        for (var i = 0; i < _data.Length / 16; i++)
        {
            var startIdx = i * 16;
            Buffer.BlockCopy(_data, startIdx, inputBuffer, 0, 16);
            _block.Decrypt(inputBuffer, outputBuffer);
            Buffer.BlockCopy(outputBuffer, 0, _data, startIdx, 16);
        }

        return RemovePadding(_data);
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
        Buffer.BlockCopy(buffer, 0, _data, size, toAppend);
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

        var aes = new Aes(key);
        return aes.Encrypt(data);
    }

    public static byte[] Aes128Decrypt(byte[] data, byte[] key)
    {
        if (key.Length != 16)
        {
            throw new InvalidKeyLenghtException(16, key.Length);
        }

        var aes = new Aes(key);
        return aes.Decrypt(data);
    }

    public static byte[] Aes192Encrypt(byte[] data, byte[] key)
    {
        if (key.Length != 24)
        {
            throw new InvalidKeyLenghtException(24, key.Length);
        }

        var aes = new Aes(key);
        return aes.Encrypt(data);
    }

    public static byte[] Aes192Decrypt(byte[] data, byte[] key)
    {
        if (key.Length != 24)
        {
            throw new InvalidKeyLenghtException(24, key.Length);
        }

        var aes = new Aes(key);
        return aes.Decrypt(data);
    }

    public static byte[] Aes256Encrypt(byte[] data, byte[] key)
    {
        if (key.Length != 32)
        {
            throw new InvalidKeyLenghtException(32, key.Length);
        }

        var aes = new Aes(key);
        return aes.Encrypt(data);
    }

    public static byte[] Aes256Decrypt(byte[] data, byte[] key)
    {
        if (key.Length != 32)
        {
            throw new InvalidKeyLenghtException(32, key.Length);
        }

        var aes = new Aes(key);
        return aes.Decrypt(data);
    }
}