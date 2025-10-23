// SSLSessionKeyExtractor.cpp - Extraction session keys TLS (SSLKEYLOGFILE format)
// Décryptage traffic capturé via ETW Microsoft-Windows-Schannel
// Partie de WinToolsSuite - forensics.malware-analysis.windows-internals
// Unicode, Win32 GUI, Threading, UI Français, RAII, CSV UTF-8, Logging
// ⚠️ AVERTISSEMENT: Outil forensics légal uniquement - interception SSL sensible

#define UNICODE
#define _UNICODE
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <commctrl.h>
#include <tdh.h>
#include <evntrace.h>
#include <evntcons.h>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <map>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publickeytoken='6595b64144ccf1df' language='*'\"")

// === ETW Provider GUID (Microsoft-Windows-Schannel) ===
// {1F678132-5938-4686-BD05-41D8FDAFD37F}
static const GUID SchannelProviderGuid = {
    0x1F678132, 0x5938, 0x4686,
    {0xBD, 0x05, 0x41, 0xD8, 0xFD, 0xAF, 0xD3, 0x7F}
};

// === RAII Wrappers ===
class TraceHandle {
    TRACEHANDLE h = 0;
public:
    explicit TraceHandle(TRACEHANDLE handle) : h(handle) {}
    ~TraceHandle() {
        if (h != 0 && h != INVALID_PROCESSTRACE_HANDLE) {
            ControlTraceW(h, nullptr, nullptr, EVENT_TRACE_CONTROL_STOP);
        }
    }
    TRACEHANDLE Get() const { return h; }
    bool IsValid() const { return h != 0 && h != INVALID_PROCESSTRACE_HANDLE; }
};

class FileHandle {
    HANDLE h = INVALID_HANDLE_VALUE;
public:
    explicit FileHandle(HANDLE handle) : h(handle) {}
    ~FileHandle() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }
    HANDLE Get() const { return h; }
    bool IsValid() const { return h != INVALID_HANDLE_VALUE; }
};

// === Structures ===
struct TLSSessionKey {
    std::wstring timestamp;
    std::wstring processName;
    std::wstring clientRandom;
    std::wstring masterSecret;
    std::wstring serverName;
    std::wstring cipherSuite;
};

// === Globals ===
HWND g_hMainWnd = nullptr;
HWND g_hListView = nullptr;
HWND g_hStatusBar = nullptr;
HWND g_hBtnStart = nullptr;
HWND g_hBtnStop = nullptr;
HWND g_hBtnExport = nullptr;
HWND g_hBtnClear = nullptr;
HINSTANCE g_hInst = nullptr;
std::vector<TLSSessionKey> g_SessionKeys;
HANDLE g_hCaptureThread = nullptr;
volatile bool g_bCapturing = false;
TRACEHANDLE g_hSession = 0;
std::wstring g_LogFile = L"SSLSessionKeyExtractor_log.txt";

// === Logging ===
void Log(const std::wstring& msg) {
    SYSTEMTIME st;
    GetLocalTime(&st);

    std::wofstream log(g_LogFile, std::ios::app);
    if (log.is_open()) {
        log << L"[" << st.wYear << L"-"
            << std::setw(2) << std::setfill(L'0') << st.wMonth << L"-"
            << std::setw(2) << std::setfill(L'0') << st.wDay << L" "
            << std::setw(2) << std::setfill(L'0') << st.wHour << L":"
            << std::setw(2) << std::setfill(L'0') << st.wMinute << L":"
            << std::setw(2) << std::setfill(L'0') << st.wSecond << L"] "
            << msg << L"\n";
    }
}

void StatusBar(const std::wstring& msg) {
    if (g_hStatusBar) {
        SendMessageW(g_hStatusBar, SB_SETTEXTW, 0, (LPARAM)msg.c_str());
    }
    Log(msg);
}

// === Helper Functions ===
std::wstring BytesToHex(const BYTE* data, size_t len) {
    std::wstringstream ss;
    ss << std::hex << std::setfill(L'0');
    for (size_t i = 0; i < len; i++) {
        ss << std::setw(2) << (int)data[i];
    }
    return ss.str();
}

std::wstring GetTimestamp() {
    SYSTEMTIME st;
    GetLocalTime(&st);

    wchar_t buf[64];
    swprintf_s(buf, L"%04d-%02d-%02d %02d:%02d:%02d",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

std::wstring GetProcessNameByPID(DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return L"PID:" + std::to_wstring(pid);

    wchar_t path[MAX_PATH];
    DWORD size = MAX_PATH;
    if (QueryFullProcessImageNameW(hProc, 0, path, &size)) {
        CloseHandle(hProc);
        wchar_t* name = wcsrchr(path, L'\\');
        return name ? (name + 1) : path;
    }

    CloseHandle(hProc);
    return L"PID:" + std::to_wstring(pid);
}

// === ETW Event Callback ===
VOID WINAPI EventRecordCallback(PEVENT_RECORD pEvent) {
    if (!g_bCapturing) return;

    // Filter Schannel provider events
    if (!IsEqualGUID(pEvent->EventHeader.ProviderId, SchannelProviderGuid)) {
        return;
    }

    // Note: Schannel ETW events do NOT directly expose master secrets
    // This is a DEMONSTRATION showing ETW structure
    // Real implementation would require:
    // 1. Kernel debugging (not feasible in user-mode)
    // 2. LSASS memory reading (requires SYSTEM privileges + anti-cheat bypass)
    // 3. Inline hooking schannel.dll (requires injection)

    // For demonstration: We capture basic TLS handshake info
    // Event IDs of interest (hypothetical, vary by Windows version):
    // - 1 : Handshake started
    // - 2 : Handshake completed
    // - 36: TLS 1.2/1.3 negotiation

    DWORD eventId = pEvent->EventHeader.EventDescriptor.Id;
    DWORD processId = pEvent->EventHeader.ProcessId;

    // Simplified: Log handshake events
    if (eventId == 1 || eventId == 2 || eventId == 36) {
        TLSSessionKey key;
        key.timestamp = GetTimestamp();
        key.processName = GetProcessNameByPID(processId);
        key.clientRandom = L"(ETW ne fournit pas - voir README)";
        key.masterSecret = L"(Non accessible en user-mode)";
        key.serverName = L"(Parser UserData requis)";
        key.cipherSuite = L"EventID:" + std::to_wstring(eventId);

        g_SessionKeys.push_back(key);

        // Update UI (post message to main thread)
        PostMessageW(g_hMainWnd, WM_USER + 1, 0, 0);
    }
}

// === ETW Trace Thread ===
DWORD WINAPI CaptureThread(LPVOID param) {
    // Start ETW trace session
    WCHAR sessionName[] = L"SSLKeyExtractorSession";

    EVENT_TRACE_PROPERTIES* props = nullptr;
    ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(sessionName) + sizeof(WCHAR);
    props = (EVENT_TRACE_PROPERTIES*)malloc(bufferSize);
    if (!props) {
        StatusBar(L"Erreur: Allocation mémoire trace properties");
        return 1;
    }

    ZeroMemory(props, bufferSize);
    props->Wnode.BufferSize = bufferSize;
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1; // QPC clock resolution
    props->Wnode.Guid = SchannelProviderGuid;
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    // Stop existing session if any
    ControlTraceW(0, sessionName, props, EVENT_TRACE_CONTROL_STOP);

    // Start new session
    TRACEHANDLE hSession = 0;
    ULONG status = StartTraceW(&hSession, sessionName, props);
    if (status != ERROR_SUCCESS) {
        free(props);
        std::wstringstream ss;
        ss << L"Erreur StartTrace: " << status << L" (admin requis)";
        StatusBar(ss.str());
        return 1;
    }

    g_hSession = hSession;

    // Enable Schannel provider
    status = EnableTraceEx2(
        hSession,
        &SchannelProviderGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE,
        0xFFFFFFFFFFFFFFFF, // All keywords
        0,
        0,
        nullptr
    );

    if (status != ERROR_SUCCESS) {
        ControlTraceW(hSession, nullptr, props, EVENT_TRACE_CONTROL_STOP);
        free(props);
        StatusBar(L"Erreur EnableTraceEx2: " + std::to_wstring(status));
        return 1;
    }

    free(props);

    // Open trace for processing
    EVENT_TRACE_LOGFILEW logfile = {0};
    logfile.LoggerName = sessionName;
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = EventRecordCallback;

    TRACEHANDLE hTrace = OpenTraceW(&logfile);
    if (hTrace == INVALID_PROCESSTRACE_HANDLE) {
        ControlTraceW(hSession, nullptr, nullptr, EVENT_TRACE_CONTROL_STOP);
        StatusBar(L"Erreur OpenTrace: " + std::to_wstring(GetLastError()));
        return 1;
    }

    StatusBar(L"Capture ETW démarrée (Schannel events)");

    // Process trace (blocking call)
    status = ProcessTrace(&hTrace, 1, nullptr, nullptr);

    CloseTrace(hTrace);

    if (g_hSession) {
        ControlTraceW(g_hSession, nullptr, nullptr, EVENT_TRACE_CONTROL_STOP);
        g_hSession = 0;
    }

    StatusBar(L"Capture arrêtée");
    return 0;
}

// === ListView Functions ===
void InitListView() {
    LVCOLUMNW lvc = {0};
    lvc.mask = LVCF_TEXT | LVCF_WIDTH;

    lvc.cx = 140; lvc.pszText = (LPWSTR)L"Timestamp"; ListView_InsertColumn(g_hListView, 0, &lvc);
    lvc.cx = 160; lvc.pszText = (LPWSTR)L"Process"; ListView_InsertColumn(g_hListView, 1, &lvc);
    lvc.cx = 320; lvc.pszText = (LPWSTR)L"Client Random"; ListView_InsertColumn(g_hListView, 2, &lvc);
    lvc.cx = 320; lvc.pszText = (LPWSTR)L"Master Secret"; ListView_InsertColumn(g_hListView, 3, &lvc);
    lvc.cx = 180; lvc.pszText = (LPWSTR)L"Server Name"; ListView_InsertColumn(g_hListView, 4, &lvc);
    lvc.cx = 120; lvc.pszText = (LPWSTR)L"Cipher Suite"; ListView_InsertColumn(g_hListView, 5, &lvc);

    ListView_SetExtendedListViewStyle(g_hListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
}

void PopulateListView() {
    ListView_DeleteAllItems(g_hListView);

    LVITEMW lvi = {0};
    lvi.mask = LVIF_TEXT;

    for (size_t i = 0; i < g_SessionKeys.size(); i++) {
        const auto& k = g_SessionKeys[i];

        lvi.iItem = (int)i;
        lvi.iSubItem = 0; lvi.pszText = (LPWSTR)k.timestamp.c_str(); ListView_InsertItem(g_hListView, &lvi);
        lvi.iSubItem = 1; lvi.pszText = (LPWSTR)k.processName.c_str(); ListView_SetItem(g_hListView, &lvi);
        lvi.iSubItem = 2; lvi.pszText = (LPWSTR)k.clientRandom.c_str(); ListView_SetItem(g_hListView, &lvi);
        lvi.iSubItem = 3; lvi.pszText = (LPWSTR)k.masterSecret.c_str(); ListView_SetItem(g_hListView, &lvi);
        lvi.iSubItem = 4; lvi.pszText = (LPWSTR)k.serverName.c_str(); ListView_SetItem(g_hListView, &lvi);
        lvi.iSubItem = 5; lvi.pszText = (LPWSTR)k.cipherSuite.c_str(); ListView_SetItem(g_hListView, &lvi);
    }
}

// === SSLKEYLOGFILE Export ===
void ExportSSLKEYLOGFILE(const std::wstring& filename) {
    FileHandle hFile(CreateFileW(filename.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!hFile.IsValid()) {
        StatusBar(L"Erreur: Impossible de créer le fichier SSLKEYLOGFILE");
        return;
    }

    // SSLKEYLOGFILE format (Wireshark compatible):
    // CLIENT_RANDOM <client_random_hex> <master_secret_hex>

    std::wstringstream ss;
    ss << L"# SSL/TLS Master Secrets (SSLKEYLOGFILE format)\n";
    ss << L"# Compatible with Wireshark: Edit > Preferences > Protocols > TLS > (Pre)-Master-Secret log filename\n";
    ss << L"# Generated by SSLSessionKeyExtractor - WinToolsSuite\n";
    ss << L"# WARNING: ETW method does NOT capture actual secrets (see README)\n\n";

    for (const auto& k : g_SessionKeys) {
        // Note: Real implementation would output valid hex here
        ss << L"# Timestamp: " << k.timestamp << L" | Process: " << k.processName << L"\n";
        ss << L"CLIENT_RANDOM " << k.clientRandom << L" " << k.masterSecret << L"\n";
    }

    std::wstring data = ss.str();
    int len = WideCharToMultiByte(CP_UTF8, 0, data.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len > 0) {
        std::vector<char> utf8(len);
        WideCharToMultiByte(CP_UTF8, 0, data.c_str(), -1, utf8.data(), len, nullptr, nullptr);
        DWORD written;
        WriteFile(hFile.Get(), utf8.data(), len - 1, &written, nullptr);
    }

    StatusBar(L"SSLKEYLOGFILE exporté: " + filename);
}

// === Window Procedure ===
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            // Legal warning
            MessageBoxW(hwnd,
                L"⚠️ AVERTISSEMENT LÉGAL ⚠️\n\n"
                L"Cet outil permet l'interception de clés de session TLS/SSL.\n\n"
                L"Usage AUTORISÉ uniquement pour:\n"
                L"- Forensics légal (enquêtes autorisées)\n"
                L"- Tests en environnement contrôlé\n"
                L"- Analyse malware en laboratoire\n\n"
                L"Usage INTERDIT:\n"
                L"- Interception non autorisée de communications tierces\n"
                L"- Violation de confidentialité\n\n"
                L"L'utilisateur assume TOUTE responsabilité légale.\n\n"
                L"LIMITATION TECHNIQUE:\n"
                L"La méthode ETW ne capture PAS les master secrets réels.\n"
                L"Voir README pour alternatives (hooking, kernel debug).",
                L"Avertissement Légal - SSLSessionKeyExtractor",
                MB_ICONWARNING | MB_OK);

            // ListView
            g_hListView = CreateWindowExW(0, WC_LISTVIEWW, nullptr,
                WS_CHILD | WS_VISIBLE | WS_BORDER | LVS_REPORT | LVS_SINGLESEL,
                10, 10, 1180, 500, hwnd, (HMENU)1, g_hInst, nullptr);
            InitListView();

            // Buttons
            g_hBtnStart = CreateWindowW(L"BUTTON", L"Démarrer Capture",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                10, 520, 140, 30, hwnd, (HMENU)2, g_hInst, nullptr);

            g_hBtnStop = CreateWindowW(L"BUTTON", L"Arrêter Capture",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
                160, 520, 140, 30, hwnd, (HMENU)3, g_hInst, nullptr);

            g_hBtnExport = CreateWindowW(L"BUTTON", L"Exporter SSLKEYLOGFILE",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                310, 520, 180, 30, hwnd, (HMENU)4, g_hInst, nullptr);

            g_hBtnClear = CreateWindowW(L"BUTTON", L"Effacer",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                500, 520, 80, 30, hwnd, (HMENU)5, g_hInst, nullptr);

            // StatusBar
            g_hStatusBar = CreateWindowExW(0, STATUSCLASSNAMEW, nullptr,
                WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
                0, 0, 0, 0, hwnd, nullptr, g_hInst, nullptr);

            StatusBar(L"SSLSessionKeyExtractor v1.0 - PRÊT (droits admin requis)");
            break;
        }

        case WM_COMMAND: {
            int id = LOWORD(wParam);

            if (id == 2) { // Démarrer capture
                g_bCapturing = true;
                g_SessionKeys.clear();
                PopulateListView();

                EnableWindow(g_hBtnStart, FALSE);
                EnableWindow(g_hBtnStop, TRUE);

                if (g_hCaptureThread) CloseHandle(g_hCaptureThread);
                g_hCaptureThread = CreateThread(nullptr, 0, CaptureThread, nullptr, 0, nullptr);
            }
            else if (id == 3) { // Arrêter capture
                g_bCapturing = false;

                if (g_hSession) {
                    ControlTraceW(g_hSession, nullptr, nullptr, EVENT_TRACE_CONTROL_STOP);
                    g_hSession = 0;
                }

                EnableWindow(g_hBtnStart, TRUE);
                EnableWindow(g_hBtnStop, FALSE);

                StatusBar(L"Capture arrêtée - " + std::to_wstring(g_SessionKeys.size()) + L" sessions capturées");
            }
            else if (id == 4) { // Exporter SSLKEYLOGFILE
                if (g_SessionKeys.empty()) {
                    StatusBar(L"Aucune session à exporter");
                    break;
                }

                wchar_t path[MAX_PATH];
                GetModuleFileNameW(nullptr, path, MAX_PATH);
                wcsrchr(path, L'\\')[1] = 0;
                wcscat_s(path, L"sslkeylog.txt");

                ExportSSLKEYLOGFILE(path);

                MessageBoxW(hwnd,
                    L"SSLKEYLOGFILE exporté.\n\n"
                    L"UTILISATION WIRESHARK:\n"
                    L"1. Edit > Preferences > Protocols > TLS\n"
                    L"2. (Pre)-Master-Secret log filename: <chemin>/sslkeylog.txt\n"
                    L"3. Ouvrir capture PCAP\n"
                    L"4. Traffic TLS sera décrypté automatiquement\n\n"
                    L"NOTE: Fichier actuel contient données DEMO (ETW limitation)",
                    L"Export Réussi", MB_ICONINFORMATION);
            }
            else if (id == 5) { // Effacer
                g_SessionKeys.clear();
                PopulateListView();
                StatusBar(L"Sessions effacées");
            }
            break;
        }

        case WM_USER + 1: { // Update UI from ETW callback
            PopulateListView();
            std::wstringstream ss;
            ss << L"Capture en cours - " << g_SessionKeys.size() << L" événements";
            StatusBar(ss.str());
            break;
        }

        case WM_SIZE: {
            int width = LOWORD(lParam);
            int height = HIWORD(lParam);

            MoveWindow(g_hListView, 10, 10, width - 20, height - 100, TRUE);
            MoveWindow(g_hBtnStart, 10, height - 80, 140, 30, TRUE);
            MoveWindow(g_hBtnStop, 160, height - 80, 140, 30, TRUE);
            MoveWindow(g_hBtnExport, 310, height - 80, 180, 30, TRUE);
            MoveWindow(g_hBtnClear, 500, height - 80, 80, 30, TRUE);
            SendMessage(g_hStatusBar, WM_SIZE, 0, 0);
            break;
        }

        case WM_DESTROY:
            g_bCapturing = false;
            if (g_hSession) {
                ControlTraceW(g_hSession, nullptr, nullptr, EVENT_TRACE_CONTROL_STOP);
            }
            if (g_hCaptureThread) {
                WaitForSingleObject(g_hCaptureThread, 2000);
                CloseHandle(g_hCaptureThread);
            }
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
    return 0;
}

// === Entry Point ===
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow) {
    g_hInst = hInstance;

    INITCOMMONCONTROLSEX icex = {0};
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES;
    InitCommonControlsEx(&icex);

    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"SSLSessionKeyExtractorClass";
    wc.hIcon = LoadIcon(nullptr, IDI_SHIELD);
    wc.hIconSm = LoadIcon(nullptr, IDI_SHIELD);

    RegisterClassExW(&wc);

    g_hMainWnd = CreateWindowExW(0, L"SSLSessionKeyExtractorClass",
        L"SSLSessionKeyExtractor v1.0 - Extraction Clés TLS (FORENSICS LÉGAL) | WinToolsSuite",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1220, 640,
        nullptr, nullptr, hInstance, nullptr);

    ShowWindow(g_hMainWnd, nCmdShow);
    UpdateWindow(g_hMainWnd);

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int)msg.wParam;
}
