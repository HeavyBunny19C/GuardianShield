using GuardianConfigManager.Helpers;

namespace GuardianConfigManager.Models;

public class AuthEntry : ViewModelBase
{
    private string _ip = "";
    private string _mac = "";
    private string _description = "";

    public string Ip
    {
        get => _ip;
        set => SetProperty(ref _ip, value);
    }

    public string Mac
    {
        get => _mac;
        set => SetProperty(ref _mac, value);
    }

    public string Description
    {
        get => _description;
        set => SetProperty(ref _description, value);
    }
}
