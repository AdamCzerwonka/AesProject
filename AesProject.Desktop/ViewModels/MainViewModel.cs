using System;
using System.IO;
using System.Security.Cryptography;
using System.Windows.Input;
using System.Text;
using System.Windows;
using AesProject.Core.Exceptions;
using AesProject.Desktop.Models;
using Microsoft.Win32;
using Aes = AesProject.Core.Aes;

namespace AesProject.Desktop.ViewModels;

public class MainViewModel : NotifyPropertyChanged
{
    public MainViewModel()
    {
        CypherCommand = new RelayCommand(CypherText);
        DecryptCommand = new RelayCommand(DecryptText);
        LoadFromFileCommand = new RelayCommand(LoadFromFile);
        SaveFileCommand = new RelayCommand(SaveFile);
        LoadFromEncryptedFileCommand = new RelayCommand(LoadFromEncryptedFile);
        SaveEncryptedFileCommand = new RelayCommand(SaveEncryptedFile);
        GenerateKeyCommand = new RelayCommand(GenerateRandomKey);
        ResetAllCommand = new RelayCommand(ResetAll);
        ResetBuffCommand = new RelayCommand(ResetBuff);
    }

    public ICommand GenerateKeyCommand { get; set; }
    public ICommand CypherCommand { get; set; }
    public ICommand DecryptCommand { get; set; }
    public ICommand LoadFromFileCommand { get; set; }
    public ICommand SaveFileCommand { get; set; }
    public ICommand LoadFromEncryptedFileCommand { get; set; }
    public ICommand SaveEncryptedFileCommand { get; set; }
    public ICommand ResetAllCommand { get; set; }
    public ICommand ResetBuffCommand { get; set; }

    private AesAlgorithm _algorithm = AesAlgorithm.Aes128;

    public AesAlgorithm Algorithm
    {
        get => _algorithm;
        set
        {
            _algorithm = value;
            OnPropertyChanged();
        }
    }


    private string? _key;

    public string? Key
    {
        get => _key;
        set
        {
            _key = value;
            OnPropertyChanged();
        }
    }

    private byte[]? _plainTextBuffer = null;

    private string? _plainText;

    public string? PlainText
    {
        get => _plainText;
        set
        {
            _plainText = value;
            OnPropertyChanged();
        }
    }

    private byte[]? _encryptedTextBuffer = null;

    private string? _encryptedText;

    public string? EncryptedText
    {
        get => _encryptedText;
        set
        {
            _encryptedText = value;
            OnPropertyChanged();
        }
    }

    private void LoadFromFile(object _)
    {
        var openFileDialog = new OpenFileDialog();
        if (openFileDialog.ShowDialog() == true)
        {
            var file = openFileDialog.FileName;
            _plainTextBuffer = File.ReadAllBytes(file);
            PlainText = Encoding.UTF8.GetString(_plainTextBuffer);
        }
    }
    
    private void LoadFromEncryptedFile(object _)
    {
        var openFileDialog = new OpenFileDialog();
        if (openFileDialog.ShowDialog() == true)
        {
            var file = openFileDialog.FileName;
            _encryptedTextBuffer = File.ReadAllBytes(file);
            EncryptedText = Encoding.UTF8.GetString(_encryptedTextBuffer);
        }
    }

    private void SaveFile(object _)
    {
        if (_plainText is null or "" && _plainTextBuffer is null)
        {
            MessageBox.Show("There is nothing to save");
            return;
        }

        var saveFileDialog = new SaveFileDialog();
        if (saveFileDialog.ShowDialog() == true)
        {
            var file = saveFileDialog.FileName;
            _plainTextBuffer ??= Encoding.UTF8.GetBytes(_plainText!);
            File.WriteAllBytes(file, _plainTextBuffer);
        }
    }
    
    private void SaveEncryptedFile(object _)
    {
        if (_encryptedText is null or "" && _encryptedTextBuffer is null)
        {
            MessageBox.Show("There is nothing to save");
            return;
        }

        var saveFileDialog = new SaveFileDialog();
        if (saveFileDialog.ShowDialog() == true)
        {
            var file = saveFileDialog.FileName;
            _encryptedTextBuffer ??= Encoding.UTF8.GetBytes(_encryptedText!);
            File.WriteAllBytes(file, _encryptedTextBuffer);
        }
    }

    private void GenerateRandomKey(object _)
    {
        var key = RandomNumberGenerator.GetBytes((int)Algorithm / 2);
        var builder = new StringBuilder();
        foreach (var b in key)
        {
            builder.Append(b.ToString("X2"));
        }

        Key = builder.ToString();
    }


    private void CypherText(object _)
    {
        if (_key is null)
        {
            MessageBox.Show("Missing key");
            return;
        }

        if (_plainText is null && _plainTextBuffer is null)
        {
            MessageBox.Show("Missing data to cypher");
            return;
        }

        _plainTextBuffer ??= Encoding.UTF8.GetBytes(_plainText!);

        Func<byte[], byte[], byte[]> encryptionFunc = Algorithm switch
        {
            AesAlgorithm.Aes128 => Aes.Aes128Encrypt,
            AesAlgorithm.Aes192 => Aes.Aes192Encrypt,
            AesAlgorithm.Aes256 => Aes.Aes256Encrypt,
            _ => throw new Exception("Failed")
        };

        var keyBytes = Encoding.UTF8.GetBytes(_key);

        try
        {
            var result = encryptionFunc(_plainTextBuffer!, keyBytes);

            var builder = new StringBuilder();
            foreach (var b in result)
            {
                builder.Append(b.ToString("X2"));
            }

            _encryptedTextBuffer = result;
            EncryptedText = builder.ToString();
        }
        catch (InvalidKeyLenghtException e)
        {
            MessageBox.Show(e.Message);
        }
    }

    private void DecryptText(object _)
    {
        if (_key is null)
        {
            MessageBox.Show("Missing key");
            return;
        }

        if (_encryptedText is null && _encryptedTextBuffer is null)
        {
            MessageBox.Show("Missing data to encrypt");
            return;
        }

        Func<byte[], byte[], byte[]> encryptionFunc = Algorithm switch
        {
            AesAlgorithm.Aes128 => Aes.Aes128Decrypt,
            AesAlgorithm.Aes192 => Aes.Aes192Decrypt,
            AesAlgorithm.Aes256 => Aes.Aes256Decrypt,
            _ => throw new Exception("Failed")
        };

        var keyBytes = Encoding.UTF8.GetBytes(_key);

        if (_encryptedTextBuffer == null)
        {
            if (_encryptedText.Length % 2 == 1)
            {
                MessageBox.Show("Invalid encrypted data length");
                return;
            }

            _encryptedTextBuffer = new byte[_encryptedText.Length >> 1];
            for (var i = 0; i < _encryptedText.Length >> 1; ++i)
            {
                _encryptedTextBuffer[i] = (byte)((GetHexVal(_encryptedText[i << 1]) << 4) +
                                                 (GetHexVal(_encryptedText[(i << 1) + 1])));
            }
        }

        try
        {
            var result = encryptionFunc(_encryptedTextBuffer, keyBytes);
            _plainTextBuffer = result;
            PlainText = Encoding.UTF8.GetString(result);
        }
        catch (InvalidKeyLenghtException e)
        {
            MessageBox.Show(e.Message);
        }
    }

    private int GetHexVal(char hex)
    {
        int val = (int)hex;
        //For uppercase A-F letters:
        //return val - (val < 58 ? 48 : 55);
        //For lowercase a-f letters:
        //return val - (val < 58 ? 48 : 87);
        //Or the two combined, but a bit slower:
        return val - (val < 58 ? 48 : (val < 97 ? 55 : 87));
    }

    private void ResetAll(object _)
    {
        PlainText = "";
        _plainTextBuffer = null;
        EncryptedText = "";
        _encryptedTextBuffer = null;
        Key = "";
        Algorithm = AesAlgorithm.Aes128;
    }

    private void ResetBuff(object _)
    {
        _plainTextBuffer = null;
        _encryptedTextBuffer = null;
    }
}