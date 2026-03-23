using System.Collections.Generic;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Controls;

namespace GuardianConfigManager.Views;

public partial class EmergencyPage : UserControl
{
    public EmergencyPage() { InitializeComponent(); }
}

public class ListToStringConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is IEnumerable<string> list)
            return string.Join(", ", list);
        return "";
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotImplementedException();
}
