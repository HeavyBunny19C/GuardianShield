using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Input;
using GuardianConfigManager.Helpers;
using GuardianConfigManager.Models;
using GuardianConfigManager.Services;
using GuardianConfigManager.Views;
using Microsoft.Win32;

namespace GuardianConfigManager.ViewModels;

public class MainViewModel : ViewModelBase
{
    private GuardianConfig _config = new();
    private ObservableCollection<AuthEntry> _authEntries = new();
    private string _configFilePath = "";
    private string _authFilePath = "";
    private int _selectedNavIndex;
    private string _statusText = "就绪";

    public GuardianConfig Config
    {
        get => _config;
        set => SetProperty(ref _config, value);
    }

    public ObservableCollection<AuthEntry> AuthEntries
    {
        get => _authEntries;
        set => SetProperty(ref _authEntries, value);
    }

    public string ConfigFilePath
    {
        get => _configFilePath;
        set => SetProperty(ref _configFilePath, value);
    }

    public string AuthFilePath
    {
        get => _authFilePath;
        set => SetProperty(ref _authFilePath, value);
    }

    public int SelectedNavIndex
    {
        get => _selectedNavIndex;
        set => SetProperty(ref _selectedNavIndex, value);
    }

    public string StatusText
    {
        get => _statusText;
        set => SetProperty(ref _statusText, value);
    }

    public ICommand OpenConfigCommand { get; }
    public ICommand SaveConfigCommand { get; }
    public ICommand OpenAuthCommand { get; }
    public ICommand SaveAuthCommand { get; }
    public ICommand AddAuthEntryCommand { get; }
    public ICommand RemoveAuthEntryCommand { get; }
    public ICommand GeneratePasswordHashCommand { get; }
    public ICommand GenerateKeyHashCommand { get; }
    public ICommand AddProtectedDirCommand { get; }
    public ICommand RemoveProtectedDirCommand { get; }
    public ICommand AddWhitelistCommand { get; }
    public ICommand RemoveWhitelistCommand { get; }
    public ICommand AddNotificationCommand { get; }
    public ICommand RemoveNotificationCommand { get; }

    public MainViewModel()
    {
        OpenConfigCommand = new RelayCommand(_ => OpenConfig());
        SaveConfigCommand = new RelayCommand(_ => SaveConfig(), _ => !string.IsNullOrEmpty(ConfigFilePath));
        OpenAuthCommand = new RelayCommand(_ => OpenAuth());
        SaveAuthCommand = new RelayCommand(_ => SaveAuth(), _ => !string.IsNullOrEmpty(AuthFilePath));
        AddAuthEntryCommand = new RelayCommand(_ => AuthEntries.Add(new AuthEntry()));
        RemoveAuthEntryCommand = new RelayCommand(p => { if (p is AuthEntry e) AuthEntries.Remove(e); });
        GeneratePasswordHashCommand = new RelayCommand(_ => GenerateHash(true));
        GenerateKeyHashCommand = new RelayCommand(_ => GenerateHash(false));
        AddProtectedDirCommand = new RelayCommand(_ => Config.Protection.Directories.Add(new ProtectedDirectory()));
        RemoveProtectedDirCommand = new RelayCommand(p => { if (p is ProtectedDirectory d) Config.Protection.Directories.Remove(d); });
        AddWhitelistCommand = new RelayCommand(_ => Config.Whitelist.Processes.Add(new WhitelistProcess()));
        RemoveWhitelistCommand = new RelayCommand(p => { if (p is WhitelistProcess w) Config.Whitelist.Processes.Remove(w); });
        AddNotificationCommand = new RelayCommand(_ => Config.Emergency.Notifications.Add(new NotificationChannel()));
        RemoveNotificationCommand = new RelayCommand(p => { if (p is NotificationChannel n) Config.Emergency.Notifications.Remove(n); });

        TryAutoDetect();
    }

    private void TryAutoDetect()
    {
        var cfgPath = YamlConfigService.GetDefaultConfigPath();
        if (!string.IsNullOrEmpty(cfgPath))
        {
            ConfigFilePath = cfgPath;
            LoadConfigFile(cfgPath);
        }

        var authPath = AuthListService.GetDefaultAuthPath();
        if (!string.IsNullOrEmpty(authPath))
        {
            AuthFilePath = authPath;
            LoadAuthFile(authPath);
        }
    }

    private string GetConfigInitialDirectory()
    {
        if (!string.IsNullOrEmpty(ConfigFilePath))
            return System.IO.Path.GetDirectoryName(ConfigFilePath) ?? "";
        return YamlConfigService.FindConfigDirUpward() ?? @"C:\ProgramData\GuardianShield\config";
    }

    private void OpenConfig()
    {
        var dlg = new OpenFileDialog
        {
            Title = "选择配置文件 (guardian_config.yaml)",
            Filter = "YAML 文件|*.yaml;*.yml|所有文件|*.*",
            InitialDirectory = GetConfigInitialDirectory()
        };
        if (dlg.ShowDialog() == true)
        {
            ConfigFilePath = dlg.FileName;
            LoadConfigFile(dlg.FileName);
        }
    }

    private void LoadConfigFile(string path)
    {
        try
        {
            Config = YamlConfigService.Load(path);
            OnPropertyChanged(nameof(Config));
            StatusText = $"已加载配置: {path}";
        }
        catch (Exception ex)
        {
            MessageBox.Show($"加载配置文件失败:\n{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void SaveConfig()
    {
        try
        {
            var dlg = new SaveFileDialog
            {
                Title = "保存配置文件",
                Filter = "YAML 文件|*.yaml;*.yml|所有文件|*.*",
                FileName = System.IO.Path.GetFileName(ConfigFilePath),
                InitialDirectory = System.IO.Path.GetDirectoryName(ConfigFilePath) ?? ""
            };
            if (dlg.ShowDialog() == true)
            {
                YamlConfigService.Save(dlg.FileName, Config);
                ConfigFilePath = dlg.FileName;
                StatusText = $"配置已保存: {dlg.FileName}";
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"保存配置文件失败:\n{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void OpenAuth()
    {
        var initDir = !string.IsNullOrEmpty(AuthFilePath)
            ? System.IO.Path.GetDirectoryName(AuthFilePath) ?? ""
            : GetConfigInitialDirectory();

        var dlg = new OpenFileDialog
        {
            Title = "选择授权清单 (auth.list)",
            Filter = "Auth List|*.list|所有文件|*.*",
            InitialDirectory = initDir
        };
        if (dlg.ShowDialog() == true)
        {
            AuthFilePath = dlg.FileName;
            LoadAuthFile(dlg.FileName);
        }
    }

    private void LoadAuthFile(string path)
    {
        try
        {
            AuthEntries = new ObservableCollection<AuthEntry>(AuthListService.Load(path));
            StatusText = $"已加载授权清单: {path}";
        }
        catch (Exception ex)
        {
            MessageBox.Show($"加载授权清单失败:\n{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void SaveAuth()
    {
        try
        {
            var dlg = new SaveFileDialog
            {
                Title = "保存授权清单",
                Filter = "Auth List|*.list|所有文件|*.*",
                FileName = System.IO.Path.GetFileName(AuthFilePath),
                InitialDirectory = System.IO.Path.GetDirectoryName(AuthFilePath) ?? ""
            };
            if (dlg.ShowDialog() == true)
            {
                AuthListService.Save(dlg.FileName, AuthEntries);
                AuthFilePath = dlg.FileName;
                StatusText = $"授权清单已保存: {dlg.FileName}";
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"保存授权清单失败:\n{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void GenerateHash(bool isPassword)
    {
        var prompt = isPassword ? "请输入管理员解锁密码:" : "请输入安装/卸载密钥:";
        var input = InputDialog.Show(prompt, "生成 SHA-256 哈希");

        if (string.IsNullOrEmpty(input)) return;

        var hash = HashService.ComputeSha256(input);
        if (isPassword)
            Config.Admin.PasswordHash = hash;
        else
            Config.Admin.InstallKeyHash = hash;

        OnPropertyChanged(nameof(Config));
        StatusText = $"已生成 SHA-256: {hash[..16]}...";
    }
}
