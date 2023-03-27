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