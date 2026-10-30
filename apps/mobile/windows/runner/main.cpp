#include <flutter/dart_project.h>
#include <flutter/flutter_view_controller.h>
#include <windows.h>

#include <string>

#include "flutter_window.h"
#include "utils.h"

namespace {

// The app asks Windows to run itself as administrator with this first, and
// the rest of the command line is PowerShell's. It used to ask for
// powershell.exe directly, and the permission prompt said "Windows
// PowerShell" with PowerShell's icon; this way it says Nebula VPN.
constexpr wchar_t kElevatedStep[] = L"--nebula-elevated ";

// Runs one PowerShell step hidden, waits for it, and returns its exit code.
// PowerShell by its full System32 path: an elevated process must not find
// its program through a search order someone else could put a file into.
int RunElevatedStep(const wchar_t* powershell_arguments) {
  wchar_t system_dir[MAX_PATH];
  const UINT length = ::GetSystemDirectoryW(system_dir, MAX_PATH);
  if (length == 0 || length >= MAX_PATH) {
    return 1;
  }
  const std::wstring powershell =
      std::wstring(system_dir) + L"\\WindowsPowerShell\\v1.0\\powershell.exe";
  std::wstring command =
      L"\"" + powershell + L"\" " + std::wstring(powershell_arguments);

  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION process{};
  if (!::CreateProcessW(powershell.c_str(), command.data(), nullptr, nullptr,
                        FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startup,
                        &process)) {
    return 1;
  }
  ::WaitForSingleObject(process.hProcess, INFINITE);
  DWORD exit_code = 1;
  ::GetExitCodeProcess(process.hProcess, &exit_code);
  ::CloseHandle(process.hThread);
  ::CloseHandle(process.hProcess);
  return static_cast<int>(exit_code);
}

}  // namespace

int APIENTRY wWinMain(_In_ HINSTANCE instance, _In_opt_ HINSTANCE prev,
                      _In_ wchar_t *command_line, _In_ int show_command) {
  // Before anything else: in this mode the app is only a named, elevated
  // launcher for one step, and never shows a window.
  if (command_line != nullptr &&
      ::wcsncmp(command_line, kElevatedStep, ::wcslen(kElevatedStep)) == 0) {
    return RunElevatedStep(command_line + ::wcslen(kElevatedStep));
  }

  // One app at a time. Launching it again -- from the Start menu, a
  // shortcut, or sign-in while it already sits in the tray -- brings the
  // running window forward instead of adding another tray icon and a second
  // owner for the same tunnel. Access denied means the running one is
  // elevated and holds the name: still running.
  HANDLE single_instance =
      ::CreateMutexW(nullptr, FALSE, L"Local\\NebulaVPN.SingleInstance");
  const DWORD mutex_error = ::GetLastError();
  if (single_instance == nullptr ? mutex_error == ERROR_ACCESS_DENIED
                                 : mutex_error == ERROR_ALREADY_EXISTS) {
    HWND running = ::FindWindowW(L"FLUTTER_RUNNER_WIN32_WINDOW", L"Nebula VPN");
    if (running != nullptr) {
      ::ShowWindow(running, ::IsIconic(running) ? SW_RESTORE : SW_SHOW);
      ::SetForegroundWindow(running);
    }
    if (single_instance != nullptr) {
      ::CloseHandle(single_instance);
    }
    return EXIT_SUCCESS;
  }

  // Attach to console when present (e.g., 'flutter run') or create a
  // new console when running with a debugger.
  if (!::AttachConsole(ATTACH_PARENT_PROCESS) && ::IsDebuggerPresent()) {
    CreateAndAttachConsole();
  }

  // Initialize COM, so that it is available for use in the library and/or
  // plugins.
  ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

  flutter::DartProject project(L"data");

  std::vector<std::string> command_line_arguments =
      GetCommandLineArguments();

  project.set_dart_entrypoint_arguments(std::move(command_line_arguments));

  FlutterWindow window(project);
  Win32Window::Point origin(10, 10);
  Win32Window::Size size(420, 720);
  if (!window.Create(L"Nebula VPN", origin, size)) {
    return EXIT_FAILURE;
  }
  window.SetQuitOnClose(true);

  ::MSG msg;
  while (::GetMessage(&msg, nullptr, 0, 0)) {
    ::TranslateMessage(&msg);
    ::DispatchMessage(&msg);
  }

  ::CoUninitialize();
  return EXIT_SUCCESS;
}
