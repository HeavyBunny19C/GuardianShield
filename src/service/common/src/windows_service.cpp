/**
 * @file windows_service.cpp
 * @brief Windows Service base class implementation
 */

#include "windows_service.h"
#include <sstream>
#include <sddl.h>

#pragma comment(lib, "Advapi32.lib")

namespace Guardian {

// Static members
WindowsService* WindowsService::s_instance = nullptr;
std::mutex WindowsService::s_instanceMutex;

WindowsService::WindowsService(
    const std::wstring& serviceName,
    const std::wstring& displayName,
    DWORD startType,
    DWORD acceptedControls)
    : m_serviceName(serviceName)
    , m_displayName(displayName)
    , m_startType(startType)
    , m_acceptedControls(acceptedControls)
    , m_statusHandle(nullptr)
    , m_state(State::Stopped)
    , m_stopping(false)
    , m_stopEvent(nullptr)
    , m_pauseEvent(nullptr)
{
    ZeroMemory(&m_status, sizeof(m_status));
    m_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    m_status.dwControlsAccepted = acceptedControls;
    m_status.dwCurrentState = SERVICE_STOPPED;
}

WindowsService::~WindowsService() {
    if (m_stopEvent) CloseHandle(m_stopEvent);
    if (m_pauseEvent) CloseHandle(m_pauseEvent);
}

int WindowsService::Run(int argc, wchar_t* argv[]) {
    {
        std::lock_guard<std::mutex> lock(s_instanceMutex);
        s_instance = this;
    }
    
    SERVICE_TABLE_ENTRYW table[] = {
        { const_cast<LPWSTR>(m_serviceName.c_str()), ServiceMain },
        { nullptr, nullptr }
    };
    
    if (!StartServiceCtrlDispatcherW(table)) {
        // Not running as service, run directly
        ServiceMainImpl(argc, argv);
    }
    
    return 0;
}

void WINAPI WindowsService::ServiceMain(DWORD argc, LPWSTR* argv) {
    std::lock_guard<std::mutex> lock(s_instanceMutex);
    if (s_instance) {
        s_instance->ServiceMainImpl(argc, argv);
    }
}

void WindowsService::ServiceMainImpl(DWORD argc, LPWSTR* argv) {
    m_statusHandle = ::RegisterServiceCtrlHandlerW(m_serviceName.c_str(), ServiceControlHandler);
    if (!m_statusHandle) return;
    
    ReportStatus(State::StartPending, 0, 120000);
    
    m_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    m_pauseEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    
    if (!m_stopEvent) {
        ReportStatus(State::Stopped);
        return;
    }
    
    ReportStatus(State::StartPending, 0, 120000);
    
    OnStart(argc, argv);
    
    if (m_state == State::Stopped) {
        return;
    }
    
    if (m_state != State::Running) {
        ReportStatus(State::Running);
    }
    
    WaitForSingleObject(m_stopEvent, INFINITE);
    
    OnStop();
    
    ReportStatus(State::Stopped);
}

void WINAPI WindowsService::ServiceControlHandler(DWORD controlCode) {
    WindowsService* inst = nullptr;
    {
        std::lock_guard<std::mutex> lock(s_instanceMutex);
        inst = s_instance;
    }
    if (!inst) return;
    
    switch (controlCode) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            inst->ReportStatus(State::StopPending);
            SetEvent(inst->m_stopEvent);
            break;
        case SERVICE_CONTROL_PAUSE:
            inst->OnPause();
            break;
        case SERVICE_CONTROL_CONTINUE:
            inst->OnContinue();
            break;
        default:
            inst->OnCustomControl(controlCode);
            break;
    }
}

void WindowsService::OnStart(DWORD argc, LPWSTR* argv) {
    // Default: do nothing
}

void WindowsService::OnStop() {
    m_stopping = true;
}

void WindowsService::OnPause() {
    // Default: do nothing
}

void WindowsService::OnContinue() {
    // Default: do nothing
}

void WindowsService::OnShutdown() {
    OnStop();
}

void WindowsService::OnCustomControl(DWORD controlCode) {
    // Default: do nothing
}

void WindowsService::ReportStatus(State state, DWORD win32ExitCode, DWORD waitHint) {
    m_state = state;
    m_status.dwCurrentState = static_cast<DWORD>(state);
    m_status.dwWin32ExitCode = win32ExitCode;
    m_status.dwWaitHint = waitHint;
    
    if (state == State::StartPending) {
        m_status.dwControlsAccepted = 0;
    } else {
        m_status.dwControlsAccepted = m_acceptedControls;
    }
    
    if (state == State::Running || state == State::Stopped) {
        m_status.dwCheckPoint = 0;
    } else {
        m_status.dwCheckPoint++;
    }
    
    if (m_statusHandle) {
        SetServiceStatus(m_statusHandle, &m_status);
    }
}

void WindowsService::SetStatus(State state) {
    ReportStatus(state);
}

void WindowsService::LogEvent(WORD eventType, const std::wstring& message) {
    HANDLE hEventLog = RegisterEventSourceW(nullptr, m_serviceName.c_str());
    if (hEventLog) {
        const wchar_t* strings[] = { message.c_str() };
        ReportEventW(hEventLog, eventType, 0, 0, nullptr, 1, 0, strings, nullptr);
        DeregisterEventSource(hEventLog);
    }
}

bool WindowsService::Install() {
#ifdef _WIN32
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) return false;
    
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    
    SC_HANDLE service = CreateServiceW(
        scm, m_serviceName.c_str(), m_displayName.c_str(),
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
        m_startType, SERVICE_ERROR_NORMAL, path,
        nullptr, nullptr, nullptr, nullptr, nullptr
    );
    
    CloseServiceHandle(scm);
    if (!service) return false;

    // Set service description
    std::wstring desc = m_displayName + L" — GuardianShield Source Code Protection System";
    SERVICE_DESCRIPTIONW sd = {};
    sd.lpDescription = const_cast<LPWSTR>(desc.c_str());
    ChangeServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, &sd);

    // Configure failure recovery: restart on failure
    SC_ACTION actions[3];
    actions[0].Type = SC_ACTION_RESTART;  actions[0].Delay = 5000;   // 5s
    actions[1].Type = SC_ACTION_RESTART;  actions[1].Delay = 30000;  // 30s
    actions[2].Type = SC_ACTION_RESTART;  actions[2].Delay = 60000;  // 60s

    SERVICE_FAILURE_ACTIONSW sfa = {};
    sfa.dwResetPeriod = 86400;
    sfa.lpRebootMsg = nullptr;
    sfa.lpCommand = nullptr;
    sfa.cActions = 3;
    sfa.lpsaActions = actions;
    ChangeServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS, &sfa);

    // DACL: SYSTEM full, Administrators full, Interactive Users query-only
    PSECURITY_DESCRIPTOR psd = nullptr;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)"
            L"(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)"
            L"(A;;CCLCSWLOCRRC;;;IU)",
            SDDL_REVISION_1, &psd, nullptr)) {
        SetServiceObjectSecurity(service, DACL_SECURITY_INFORMATION, psd);
        LocalFree(psd);
    }

    CloseServiceHandle(service);
    return true;
#else
    return false;
#endif
}

bool WindowsService::Uninstall() {
#ifdef _WIN32
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) return false;
    
    SC_HANDLE service = OpenServiceW(scm, m_serviceName.c_str(), DELETE);
    CloseServiceHandle(scm);
    
    if (!service) return false;
    
    bool result = DeleteService(service) != FALSE;
    CloseServiceHandle(service);
    return result;
#else
    return false;
#endif
}

bool WindowsService::Start() {
#ifdef _WIN32
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;

    SC_HANDLE svc = OpenServiceW(scm, m_serviceName.c_str(), SERVICE_START);
    if (!svc) {
        CloseServiceHandle(scm);
        return false;
    }

    BOOL ok = StartServiceW(svc, 0, nullptr);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok != FALSE;
#else
    return false;
#endif
}

bool WindowsService::Stop() {
    OnStop();
    return true;
}

// ServiceInstaller Implementation
bool ServiceInstaller::Install(const std::wstring& serviceName,
                                const std::wstring& displayName,
                                const std::wstring& binaryPath,
                                DWORD startType,
                                const std::wstring& dependencies,
                                const std::wstring& account,
                                const std::wstring& password) {
#ifdef _WIN32
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) return false;
    
    SC_HANDLE service = CreateServiceW(
        scm, serviceName.c_str(), displayName.c_str(),
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
        startType, SERVICE_ERROR_NORMAL, binaryPath.c_str(),
        nullptr, nullptr,
        dependencies.empty() ? nullptr : dependencies.c_str(),
        account.empty() ? nullptr : account.c_str(),
        password.empty() ? nullptr : password.c_str()
    );
    
    CloseServiceHandle(scm);
    if (!service) return false;
    
    CloseServiceHandle(service);
    return true;
#else
    return false;
#endif
}

bool ServiceInstaller::Uninstall(const std::wstring& serviceName) {
#ifdef _WIN32
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) return false;
    
    SC_HANDLE service = OpenServiceW(scm, serviceName.c_str(), DELETE);
    CloseServiceHandle(scm);
    
    if (!service) return false;
    
    bool result = DeleteService(service) != FALSE;
    CloseServiceHandle(service);
    return result;
#else
    return false;
#endif
}

bool ServiceInstaller::IsInstalled(const std::wstring& serviceName) {
#ifdef _WIN32
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;
    
    SC_HANDLE service = OpenServiceW(scm, serviceName.c_str(), SERVICE_QUERY_STATUS);
    CloseServiceHandle(scm);
    
    if (!service) return false;
    
    CloseServiceHandle(service);
    return true;
#else
    return false;
#endif
}

bool ServiceInstaller::IsRunning(const std::wstring& serviceName) {
#ifdef _WIN32
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;

    SC_HANDLE svc = OpenServiceW(scm, serviceName.c_str(), SERVICE_QUERY_STATUS);
    if (!svc) {
        CloseServiceHandle(scm);
        return false;
    }

    SERVICE_STATUS status = {};
    BOOL ok = QueryServiceStatus(svc, &status);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    return ok && status.dwCurrentState == SERVICE_RUNNING;
#else
    return false;
#endif
}

bool ServiceInstaller::Start(const std::wstring& serviceName) {
#ifdef _WIN32
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;

    SC_HANDLE svc = OpenServiceW(scm, serviceName.c_str(), SERVICE_START);
    if (!svc) {
        CloseServiceHandle(scm);
        return false;
    }

    BOOL ok = StartServiceW(svc, 0, nullptr);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok != FALSE;
#else
    return false;
#endif
}

bool ServiceInstaller::Stop(const std::wstring& serviceName) {
#ifdef _WIN32
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;

    SC_HANDLE svc = OpenServiceW(scm, serviceName.c_str(), SERVICE_STOP);
    if (!svc) {
        CloseServiceHandle(scm);
        return false;
    }

    SERVICE_STATUS status = {};
    BOOL ok = ControlService(svc, SERVICE_CONTROL_STOP, &status);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok != FALSE;
#else
    return false;
#endif
}

} // namespace Guardian
