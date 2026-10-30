; Free, reproducible x64 installer. Compile with Inno Setup 6 (ISCC.exe).
#define AppName "Nebula VPN"
#define AppPublisher "Nebula VPN"
#define BundleDir "..\..\build\windows\x64\runner\Release"
; Read from the built exe, which Flutter stamps with pubspec.yaml's version.
; This was a hardcoded "1.0.0", so Windows listed every install as 1.0.0.
#define AppVersion GetVersionNumbersString(BundleDir + "\nebula_mobile.exe")

[Setup]
AppId={{A51C4A39-12AF-4A42-91CE-75906B2C4FD2}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
OutputDir=..\..\dist
OutputBaseFilename=NebulaVPN-windows-x64-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\NebulaVPN.exe
; Flutter's Windows engine needs Windows 10.
MinVersion=10.0
; The app, and the elevated VPN engine it starts, may be running. The app
; ends when asked through the Restart Manager (see flutter_window.cpp);
; force, should anything still hold a file, rather than a dialog asking the
; person to find the tray icon -- the elevated helper takes the tunnel down
; when the app is gone either way.
CloseApplications=force
SetupIconFile=..\runner\resources\app_icon.ico

; The exe used to be Nebula.exe, a name Windows takes for a game's: Game Bar
; attached to it, and in Windows Sandbox the guest crashed (bug check 0x3B)
; seconds after it started. An upgrade removes the old file.
[InstallDelete]
Type: files; Name: "{app}\Nebula.exe"

[Files]
Source: "{#BundleDir}\nebula_mobile.exe"; DestDir: "{app}"; DestName: "NebulaVPN.exe"; Flags: ignoreversion
Source: "{#BundleDir}\*"; DestDir: "{app}"; Excludes: "nebula_mobile.exe"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\NebulaVPN.exe"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\NebulaVPN.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Run]
; The app starts its VPN engine as administrator from this folder, so only
; administrators may change what is in it, wherever it is installed. A folder
; outside Program Files inherits "Authenticated Users: Modify" (seen on
; D:\apps), and any program of the person's could swap the engine for its own
; and have it run as administrator on the next connect. Not recursive: the
; change flows to everything that inherits, and {app}\tunnel, which inherits
; nothing (administrators only, with the WireGuard key), stays as it is.
Filename: "{sys}\icacls.exe"; Parameters: """{app}"" /inheritance:r /grant:r *S-1-5-32-544:(OI)(CI)F *S-1-5-18:(OI)(CI)F *S-1-5-32-545:(OI)(CI)RX /C /Q"; Flags: runhidden waituntilterminated; StatusMsg: "Securing the install folder..."
; shellexec: the app asks for administrator rights, and launched directly
; (CreateProcess) Windows refuses it with error 740 instead of prompting
; (seen installing 0.1.30, 2026-10-23). ShellExecute shows the UAC prompt.
Filename: "{app}\NebulaVPN.exe"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent shellexec

; A WireGuard tunnel runs as a Windows service whose config (private key
; included) lives in {app}\tunnel, readable only by administrators. Left
; behind, the service would point at a config the uninstall deleted, and the
; key would stay on disk. sc.exe rather than wireguard.exe: the latter
; answers a tunnel that is not there with a message box that waits for OK.
[UninstallRun]
Filename: "{sys}\sc.exe"; Parameters: "stop WireGuardTunnel$nebula"; Flags: runhidden waituntilterminated; RunOnceId: "StopTunnel"
Filename: "{sys}\sc.exe"; Parameters: "delete WireGuardTunnel$nebula"; Flags: runhidden waituntilterminated; RunOnceId: "DeleteTunnel"
; "Start when you sign in" (Settings) writes this value; without this the
; next sign-in would look for an exe that is gone.
Filename: "{sys}\reg.exe"; Parameters: "delete ""HKCU\Software\Microsoft\Windows\CurrentVersion\Run"" /v ""Nebula VPN"" /f"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveLoginItem"

[UninstallDelete]
Type: filesandordirs; Name: "{app}\tunnel"
