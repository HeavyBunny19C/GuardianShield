using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Windows.Controls;
using System.Windows.Data;

namespace GuardianConfigManager.Views;

public partial class KeysPage : UserControl
{
    public KeysPage() { InitializeComponent(); }
}

public class PcrIndicesConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is List<int> list)
            return string.Join(", ", list);
        return "";
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is string s && !string.IsNullOrWhiteSpace(s))
        {
            return s.Split(',', StringSplitOptions.RemoveEmptyEntries)
                .Select(x => int.TryParse(x.Trim(), out var v) ? v : 0)
                .ToList();
        }
        return new List<int>();
    }
}
