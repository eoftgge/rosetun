; Compiled by installer\build.ps1, which passes AppVersion, BuildDir and SingBoxDir.
#ifndef AppVersion
  #error Run installer\build.ps1 instead of compiling this script directly
#endif

#define AppName "Rosetun"
#define GuiExe "rosetun-gui.exe"
#define HelperExe "rosetun-helper-privileged.exe"

[Setup]
; Never change AppId: upgrades and the uninstaller find the installed copy by it.
AppId={{833B7718-C11A-4F97-9ABC-6967646F9DBB}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppName}
VersionInfoVersion={#AppVersion}
DefaultDirName={autopf}\{#AppName}
; The helper runs as SYSTEM from this folder, so it must stay writable by
; administrators only, as Program Files is.
DisableDirPage=yes
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputBaseFilename=rosetun-{#AppVersion}-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ShowLanguageDialog=auto
; The [Code] section stops the GUI and the service itself.
CloseApplications=no
UninstallDisplayName={#AppName}
UninstallDisplayIcon={app}\{#GuiExe}
SetupLogging=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"

[CustomMessages]
english.PreparingEngine=Preparing the engine...
russian.PreparingEngine=Подготовка ядра...
english.ServiceFailed=The Rosetun service could not be set up (code %1). Restart the computer and run the installer again.
russian.ServiceFailed=Не удалось настроить службу Rosetun (код %1). Перезагрузите компьютер и запустите установщик ещё раз.

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#BuildDir}\{#GuiExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BuildDir}\{#HelperExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BuildDir}\rosetun.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SingBoxDir}\sing-box.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SingBoxDir}\LICENSE"; DestDir: "{app}\licenses"; DestName: "sing-box.txt"
Source: "..\crates\rosetun-gui\assets\fonts\OFL-*.txt"; DestDir: "{app}\licenses"

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#GuiExe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#GuiExe}"; Tasks: desktopicon

[Run]
; Without runasoriginaluser the GUI would inherit the installer's elevation and
; keep its configuration in the wrong profile.
Filename: "{app}\{#GuiExe}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallDelete]
; Created by the service, not by the installer.
Type: filesandordirs; Name: "{app}\data"

[Code]
const
  ServiceName = 'Rosetun';

procedure RunHidden(const FileName, Params: String; var ResultCode: Integer);
begin
  if not Exec(FileName, Params, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    ResultCode := -1;
end;

procedure StopRunningCopies();
var
  ResultCode: Integer;
begin
  // The GUI holds no state that a kill loses: the configuration is saved atomically.
  RunHidden(ExpandConstant('{sys}\taskkill.exe'), '/F /IM {#GuiExe}', ResultCode);
  // net stop waits for the service to stop and fails harmlessly when there is none.
  RunHidden(ExpandConstant('{sys}\net.exe'), 'stop ' + ServiceName, ResultCode);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  StopRunningCopies();
  Result := '';
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    WizardForm.StatusLabel.Caption := CustomMessage('PreparingEngine');
    // Defender scans a new executable on its first launch, which can outlast
    // the helper's timeouts. Doing it here keeps the scan out of the first connect.
    RunHidden(ExpandConstant('{app}\sing-box.exe'), 'version', ResultCode);
    RunHidden(ExpandConstant('{app}\{#HelperExe}'), '--install-service', ResultCode);
    if ResultCode <> 0 then
      SuppressibleMsgBox(FmtMessage(CustomMessage('ServiceFailed'), [IntToStr(ResultCode)]),
        mbError, MB_OK, IDOK);
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    RunHidden(ExpandConstant('{sys}\taskkill.exe'), '/F /IM {#GuiExe}', ResultCode);
    RunHidden(ExpandConstant('{app}\{#HelperExe}'), '--uninstall-service', ResultCode);
    // Autostart is per user. Only the current user's values are reachable here.
    RegDeleteValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Run', 'Rosetun');
    RegDeleteValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run', 'Rosetun');
  end;
end;
