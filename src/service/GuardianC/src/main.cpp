/**
 * @file main.cpp
 * @brief GuardianC application entry point
 *
 * GuardianC is a user-mode monitoring application (not a Windows service).
 * It provides ETW event collection, heartbeat monitoring of GuardianA/B,
 * and runs silently in the background.
 */

#include "guardian_c.h"
#include "../../common/include/install_key.h"
#include "../../common/include/config.h"

#include <Windows.h>
#include <stdlib.h>

using namespace Guardian;

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

    if (argc > 1) {
        if (wcscmp(argv[1], L"--install") == 0) {
            if (!Guardian::VerifyInstallKey(argc, argv, GetCachedInstallKeyHash())) {
                MessageBoxW(nullptr, L"密钥验证失败，安装被拒绝。", L"GuardianShield", MB_OK | MB_ICONERROR);
                return 1;
            }
            return GuardianC::InstallAutoStart() ? 0 : 1;
        }

        if (wcscmp(argv[1], L"--uninstall") == 0) {
            if (!Guardian::VerifyInstallKey(argc, argv, GetCachedInstallKeyHash())) {
                MessageBoxW(nullptr, L"密钥验证失败，卸载被拒绝。", L"GuardianShield", MB_OK | MB_ICONERROR);
                return 1;
            }
            return GuardianC::UninstallAutoStart() ? 0 : 1;
        }

        if (wcscmp(argv[1], L"--status") == 0) {
            wprintf(L"=== GuardianC (winmon) Status ===\n");
            Config cfg(L"C:\\ProgramData\\GuardianShield\\config\\guardian_config.yaml");
            cfg.Load();
            const wchar_t* srcNames[] = { L"FILE (YAML)", L"CACHE", L"DEFAULT" };
            int srcIdx = static_cast<int>(cfg.GetConfigSource());
            wprintf(L"  Config:   loaded from %s\n", (srcIdx >= 0 && srcIdx <= 2) ? srcNames[srcIdx] : L"UNKNOWN");
            return 0;
        }

        if (wcscmp(argv[1], L"--silent") == 0) {
            // Fall through to normal run
        } else {
            return 1;
        }
    }

    HANDLE hMutex = CreateMutexW(nullptr, TRUE, L"Global\\GuardianCMutex");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        if (hMutex) CloseHandle(hMutex);
        return 1;
    }

    GuardianC app;
    int result = app.Run();

    if (hMutex) {
        ReleaseMutex(hMutex);
        CloseHandle(hMutex);
    }

    return result;
}
