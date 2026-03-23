/**
 * @file main.cpp
 * @brief GuardianA service entry point
 */

#include "guardian_a.h"
#include "../../common/include/logger.h"
#include "../../common/include/windows_service.h"
#include "../../common/include/install_key.h"
#include "../../common/include/config.h"

#include <Windows.h>
#include <stdlib.h>

using namespace Guardian;

static const std::wstring SERVICE_NAME = L"WinDefenderCore";

static std::string GetCachedInstallKeyHash() {
    try {
        Config cfg(L"C:\\ProgramData\\GuardianShield\\config\\guardian_config.yaml");
        cfg.Load();
        return cfg.GetInstallKeyHash();
    } catch (...) { return ""; }
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, LPWSTR, int) {
    int argc = __argc;
    wchar_t** argv = __wargv;

    GuardianA service;

    if (argc > 1) {
        if (wcscmp(argv[1], L"-install") == 0) {
            if (!VerifyInstallKey(argc, argv, GetCachedInstallKeyHash())) {
                MessageBoxW(nullptr, L"密钥验证失败，安装被拒绝。", L"GuardianShield", MB_OK | MB_ICONERROR);
                return 1;
            }
            if (service.Install()) {
                return 0;
            }
            return 1;
        }

        if (wcscmp(argv[1], L"-uninstall") == 0) {
            if (!VerifyInstallKey(argc, argv, GetCachedInstallKeyHash())) {
                MessageBoxW(nullptr, L"密钥验证失败，卸载被拒绝。", L"GuardianShield", MB_OK | MB_ICONERROR);
                return 1;
            }
            ServiceInstaller::Stop(SERVICE_NAME);
            return service.Uninstall() ? 0 : 1;
        }

        if (wcscmp(argv[1], L"-start") == 0) {
            if (!ServiceInstaller::IsInstalled(SERVICE_NAME)) return 1;
            if (ServiceInstaller::IsRunning(SERVICE_NAME)) return 0;
            return ServiceInstaller::Start(SERVICE_NAME) ? 0 : 1;
        }

        if (wcscmp(argv[1], L"-stop") == 0) {
            if (!ServiceInstaller::IsInstalled(SERVICE_NAME)) return 1;
            if (!ServiceInstaller::IsRunning(SERVICE_NAME)) return 0;
            return ServiceInstaller::Stop(SERVICE_NAME) ? 0 : 1;
        }

        if (wcscmp(argv[1], L"-status") == 0) {
            wprintf(L"=== GuardianA (WinDefenderCore) Status ===\n");
            bool svcRunning = ServiceInstaller::IsRunning(SERVICE_NAME);
            wprintf(L"  Service:  %s\n", svcRunning ? L"RUNNING" : L"STOPPED");

            Config cfg(L"C:\\ProgramData\\GuardianShield\\config\\guardian_config.yaml");
            cfg.Load();
            const wchar_t* srcNames[] = { L"FILE (YAML)", L"CACHE", L"DEFAULT" };
            int srcIdx = static_cast<int>(cfg.GetConfigSource());
            wprintf(L"  Config:   loaded from %s\n", (srcIdx >= 0 && srcIdx <= 2) ? srcNames[srcIdx] : L"UNKNOWN");

            auto dirs = cfg.GetProtectedDirectories();
            wprintf(L"  Protected dirs: %zu\n", dirs.size());
            for (const auto& d : dirs) {
                DWORD a = GetFileAttributesW(d.path.c_str());
                wprintf(L"    [%s] %s\n",
                    (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY)) ? L"OK" : L"MISSING",
                    d.path.c_str());
            }

            HANDLE hDriver = CreateFileW(L"\\\\.\\GuardMonitor", GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
            bool drvOk = (hDriver != INVALID_HANDLE_VALUE);
            if (drvOk) CloseHandle(hDriver);
            wprintf(L"  Driver:   %s\n", drvOk ? L"CONNECTED" : L"NOT LOADED");

            return 0;
        }

        return 1;
    }

    return service.Run(argc, argv);
}
