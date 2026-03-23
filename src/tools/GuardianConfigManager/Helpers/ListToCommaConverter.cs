using System.Globalization;
using System.Windows.Data;

namespace GuardianConfigManager.Helpers;

public class ListToCommaConverter : IValueConverter
{
    public object? Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is List<string> list)
            return string.Join(", ", list);
        return "";
    }

    public object? ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is string s)
            return s.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).ToList();
        return new List<string>();
    }
}
