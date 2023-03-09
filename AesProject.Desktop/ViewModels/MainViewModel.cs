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
        LoadFromFileCommand = new RelayCommand(LoadFromFile);
        GenerateKeyCommand = new RelayCommand(GenerateRandomKey);
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

        Func<byte[], byte[], byte[]> encryptionFunc = Algorithm switch
        {
            AesAlgorithm.Aes128 => Aes.Aes128Encrypt,
            AesAlgorithm.Aes192 => Aes.Aes192Encrypt,
            AesAlgorithm.Aes256 => Aes.Aes256Encrypt,
            _ => throw new Exception("Failed")
        };

        var keyBytes = Encoding.UTF8.GetBytes(Key);
        var inputBytes = Encoding.UTF8.GetBytes(PublicText);
        try
        {
            var result = encryptionFunc(inputBytes, keyBytes);

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