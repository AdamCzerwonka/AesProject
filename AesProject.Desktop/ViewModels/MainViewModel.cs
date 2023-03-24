using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Windows.Input;
using System.Text;
using System.Windows;
using AesProject.Core.ArrayExtensions;
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
        LoadFromEncryptedFileCommand = new RelayCommand(LoadEncryptedFromFile);
        SaveEncryptedFileCommand = new RelayCommand(SaveEncryptedFile);
        GenerateKeyCommand = new RelayCommand(GenerateRandomKey);
        ResetAllCommand = new RelayCommand(ResetAll);
        ResetBuffCommand = new RelayCommand(ResetBuff);
    }

    #region Commands

    public ICommand GenerateKeyCommand { get; }
    public ICommand CypherCommand { get; }
    public ICommand DecryptCommand { get; }
    public ICommand LoadFromFileCommand { get; }
    public ICommand SaveFileCommand { get; }
    public ICommand LoadFromEncryptedFileCommand { get; }
    public ICommand SaveEncryptedFileCommand { get; }
    public ICommand ResetAllCommand { get; }
    public ICommand ResetBuffCommand { get; }

    #endregion

    #region Properties

    private bool _useFileAsInput;

    public bool UseFileAsInput
    {
        get => _useFileAsInput;
        set
        {
            _useFileAsInput = value;
            OnPropertyChanged();
        }
    }

    private string _elapsedTime = string.Empty;

    public string ElapsedTime
    {
        get => _elapsedTime;
        set
        {
            _elapsedTime = value;
            OnPropertyChanged();
        }
    }

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
    private bool _useTextAsInput;

    public string? EncryptedText
    {
        get => _encryptedText;
        set
        {
            _encryptedText = value;
            OnPropertyChanged();
        }
    }

    #endregion

    private string? _plainTextFileName;
    private string? _encryptedTextFileName;

    private void LoadFromFile(object _)
    {
        var openFileDialog = new OpenFileDialog();
        if (openFileDialog.ShowDialog() != true)
        {
            return;
        }

        _plainTextFileName = openFileDialog.FileName;
        UseFileAsInput = true;
        PlainText = "File loaded";
    }

    private void LoadEncryptedFromFile(object _)
    {
        var openFileDialog = new OpenFileDialog();
        if (openFileDialog.ShowDialog() != true)
        {
            return;
        }
        
        _encryptedTextFileName = openFileDialog.FileName;
        UseFileAsInput = true;
        EncryptedText = "File loaded";
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

        if ((_plainText is null && !UseFileAsInput) || (_plainTextFileName is null && UseFileAsInput))
        {
            MessageBox.Show("Missing data to cypher");
            return;
        }


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
            var watch = new Stopwatch();
            watch.Start();
            if (_plainTextFileName is not null && UseFileAsInput)
            {
                var aes = new Aes(keyBytes);
                _encryptedTextBuffer = aes.Encrypt(_plainTextFileName);
                EncryptedText = _encryptedTextBuffer.GetBytesAsString();
                _plainTextFileName = null;
                UseFileAsInput = false;
            }
            else
            {
                _plainTextBuffer = Encoding.UTF8.GetBytes(_plainText!);
                _encryptedTextBuffer = encryptionFunc(_plainTextBuffer, keyBytes);
                EncryptedText = _encryptedTextBuffer.GetBytesAsString();
            }

            watch.Stop();
            ElapsedTime = $"Finished in: {watch.ElapsedMilliseconds}ms";
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

        if ((_encryptedText is null && !UseFileAsInput) || (_encryptedTextFileName is null && UseFileAsInput))
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

        var watch = new Stopwatch();
        watch.Start();
        
        try
        {
            if (_encryptedTextFileName is not null && UseFileAsInput)
            {
                var aes = new Aes(keyBytes);
                _plainTextBuffer = aes.Decrypt(_encryptedTextFileName);
                PlainText = Encoding.UTF8.GetString(_plainTextBuffer);
                _encryptedTextFileName = null;
                UseFileAsInput = false;
            }
            else
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
                
                var result = encryptionFunc(_encryptedTextBuffer, keyBytes);
                _plainTextBuffer = result;
                PlainText = Encoding.UTF8.GetString(result);
            }
            
            
            watch.Stop();
            ElapsedTime = $"Finished in: {watch.ElapsedMilliseconds}ms";
        }
        catch (InvalidKeyLenghtException e)
        {
            MessageBox.Show(e.Message);
        }
    }

    private int GetHexVal(char hex)
    {
        int val = hex;
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