using System.Windows.Input;
using System.Text;
using AesProject.Core;


namespace AesProject.Desktop;

public class ViewModel : NotifyPropertyChanged
{
    public ViewModel()
    {
        CypherCommand = new RelayCommand(CypherText);
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

    private string? _publicText;

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

    private void CypherText(object _)
    {
        if (Key is null || PublicText is null)
        {
            return;
        }
        
        var keyBytes = Encoding.UTF8.GetBytes(Key);
        var inputBytes = Encoding.UTF8.GetBytes(PublicText);
        var result = Aes.Aes128Encrypt(inputBytes, keyBytes);

        var builder = new StringBuilder();
        foreach (var b in result)
        {
            builder.Append(b.ToString("X2"));
        }
        
        EncryptedInput =  builder.ToString();
    }
}