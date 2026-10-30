#include "flutter_window.h"

#include <algorithm>
#include <optional>
#include <string>
#include <vector>

#include "flutter/generated_plugin_registrant.h"

FlutterWindow::FlutterWindow(const flutter::DartProject& project)
    : project_(project) {}

FlutterWindow::~FlutterWindow() {}

bool FlutterWindow::OnCreate() {
  if (!Win32Window::OnCreate()) {
    return false;
  }

  RECT frame = GetClientArea();

  // The size here must match the window dimensions to avoid unnecessary surface
  // creation / destruction in the startup path.
  flutter_controller_ = std::make_unique<flutter::FlutterViewController>(
      frame.right - frame.left, frame.bottom - frame.top, project_);
  // Ensure that basic setup of the controller was successful.
  if (!flutter_controller_->engine() || !flutter_controller_->view()) {
    return false;
  }
  RegisterPlugins(flutter_controller_->engine());
  SetChildContent(flutter_controller_->view()->GetNativeWindow());

  // Started at sign-in ("--hidden", see login_item.dart): the window stays
  // in the tray until it is opened from there.
  const std::vector<std::string>& arguments =
      project_.dart_entrypoint_arguments();
  const bool hidden = std::find(arguments.begin(), arguments.end(),
                                "--hidden") != arguments.end();
  flutter_controller_->engine()->SetNextFrameCallback([this, hidden]() {
    if (!hidden) {
      this->Show();
    }
  });

  // Flutter can complete the first frame before the "show window" callback is
  // registered. The following call ensures a frame is pending to ensure the
  // window is shown. It is a no-op if the first frame hasn't completed yet.
  flutter_controller_->ForceRedraw();

  return true;
}

void FlutterWindow::OnDestroy() {
  if (flutter_controller_) {
    flutter_controller_ = nullptr;
  }

  Win32Window::OnDestroy();
}

LRESULT
FlutterWindow::MessageHandler(HWND hwnd, UINT const message,
                              WPARAM const wparam,
                              LPARAM const lparam) noexcept {
  // Windows ending the session, or an installer through the Restart Manager,
  // asking the app to end -- not a person closing the window, which hides it
  // to the tray and keeps the VPN up. End for real: the elevated helper sees
  // the app gone and takes the tunnel down, and the files it held can be
  // replaced. Ahead of the plugins, so the tray's close handling cannot
  // swallow it. Destroying the window skips WM_CLOSE altogether.
  if (message == WM_QUERYENDSESSION) {
    return TRUE;
  }
  if (message == WM_ENDSESSION && wparam) {
    DestroyWindow(hwnd);
    return 0;
  }

  // Give Flutter, including plugins, an opportunity to handle window messages.
  if (flutter_controller_) {
    std::optional<LRESULT> result =
        flutter_controller_->HandleTopLevelWindowProc(hwnd, message, wparam,
                                                      lparam);
    if (result) {
      return *result;
    }
  }

  switch (message) {
    case WM_FONTCHANGE:
      flutter_controller_->engine()->ReloadSystemFonts();
      break;
  }

  return Win32Window::MessageHandler(hwnd, message, wparam, lparam);
}
