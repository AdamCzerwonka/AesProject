using System;
using System.Globalization;
using System.Windows.Data;
using AesProject.Desktop.Models;

namespace AesProject.Desktop;

public class AesValueConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var algo = (AesAlgorithm)value;
        var enumAsString = Enum.GetName(algo);
        return (string)parameter == enumAsString;
    }

    public object? ConvertBack(object value, Type targetType, object? parameter, CultureInfo culture)
    {
        var enumValue = Enum.Parse<AesAlgorithm>((string)parameter!);
        return (bool)value ? enumValue : null;
    }
}