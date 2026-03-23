using System.Windows;

namespace GuardianConfigManager.Views;

public partial class InputDialog : Window
{
    public string Result { get; private set; } = "";

    public InputDialog(string prompt, string title)
    {
        InitializeComponent();
        Title = title;
        PromptText.Text = prompt;
        InputBox.Focus();
    }

    private void Ok_Click(object sender, RoutedEventArgs e)
    {
        Result = InputBox.Password;
        DialogResult = true;
    }

    public static string? Show(string prompt, string title, Window? owner = null)
    {
        var dlg = new InputDialog(prompt, title);
        if (owner != null) dlg.Owner = owner;
        return dlg.ShowDialog() == true ? dlg.Result : null;
    }
}
