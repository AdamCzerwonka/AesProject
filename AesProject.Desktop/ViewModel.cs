using System;
using System.IO;
using System.Security.Cryptography;
using System.Windows.Input;
using System.Text;
using System.Windows;
using AesProject.Core.Exceptions;
using Microsoft.Win32;
using AesProject.Core;
using Aes = AesProject.Core.Aes;

namespace AesProject.Desktop;

public class ViewModel : NotifyPropertyChanged
{
    public ViewModel()
    {
        CypherCommand = new RelayCommand(CypherText);
        LoadFromFileCommand = new RelayCommand(LoadFromFile);
        GenerateKeyCommand = new RelayCommand(GenerateRandomKey);
    }

    private void GenerateRandomKey(object _)
    {
        var key = RandomNumberGenerator.GetBytes(8);
        var builder = new StringBuilder();
        foreach (var b in key)
        {
            builder.Append(b.ToString("X2"));
        }

        Key = builder.ToString();
    }

    public ICommand GenerateKeyCommand { get; set; }

    private void LoadFromFile(object _)
    {
        var openFileDialog = new OpenFileDialog();
        if (openFileDialog.ShowDialog() == true)
        {
            var file = openFileDialog.FileName;
            Console.WriteLine("Test");
            _buffer = File.ReadAllBytes(file);
        }
    }

    private byte[] _buffer = null!;

    private string? _key = "Thats my Kung Fu";

    public string? Key
    {
        get => _key;
        set
        {
            _key = value;
            OnPropertyChanged();
        }
    }

    private string? _publicText = "Test";

    public string? PublicText
    {
        get => _publicText;
        set
        {
            _publicText = value;
            OnPropertyChanged();
        }
    }

    private string? _encryptedInput;

    public string? EncryptedInput
    {
        get => _encryptedInput;
        set
        {
            _encryptedInput = value;
            OnPropertyChanged();
        }
    }

    public ICommand CypherCommand { get; set; }

    public ICommand LoadFromFileCommand { get; set; }

    private void CypherText(object _)
    {
        if (Key is null || PublicText is null)
        {
            return;
        }

        var keyBytes = Encoding.UTF8.GetBytes(Key);
        var inputBytes = Encoding.UTF8.GetBytes(PublicText);
        try
        {
            var result = Aes.Aes128Encrypt(_buffer, keyBytes);

            var builder = new StringBuilder();
            foreach (var b in result)
            {
                builder.Append(b.ToString("X2"));
            }

            EncryptedInput = builder.ToString();
        }
        catch (InvalidKeyLenghtException e)
        {
            MessageBox.Show(e.Message);
        }
    }
}