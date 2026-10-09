; Compiled by installer\build.ps1, which passes AppVersion, BuildDir, SingBoxDir and LicensesDir.
#ifndef AppVersion
  #error Run installer\build.ps1 instead of compiling this script directly
#endif
#ifndef FileVersion
  #error Run installer\build.ps1 to provide the numeric file version
#endif
#ifndef LicensesDir
  #error Run installer\build.ps1 to provide the licenses directory
#endif

#define AppName "Rosetun"
#define GuiExe "rosetun-gui.exe"
#define HelperExe "rosetun-helper-privileged.exe"
#define TempHelperExe "rosetun-install-check.exe"

[Setup]
; Never change AppId: upgrades and the uninstaller find the installed copy by it.
AppId={{833B7718-C11A-4F97-9ABC-6967646F9DBB}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppName}
VersionInfoVersion={#FileVersion}
VersionInfoTextVersion={#AppVersion}
VersionInfoProductTextVersion={#AppVersion}
DefaultDirName={autopf}\{#AppName}
; Verification and protected ACLs keep this folder safe for the SYSTEM service.
DisableDirPage=auto
; An upgrade stays in its previously selected folder.
UsePreviousAppDir=yes
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
SetupIconFile=..\crates\rosetun-gui\assets\rosetun.ico
SetupLogging=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"

[CustomMessages]
english.PreparingEngine=Preparing the engine...
russian.PreparingEngine=Подготовка ядра...
english.ServiceFailed=The Rosetun service could not be set up (code %1). Restart the computer and run the installer again.
russian.ServiceFailed=Не удалось настроить службу Rosetun (код %1). Перезагрузите компьютер и запустите установщик ещё раз.
english.DirInvalid=Choose an absolute folder below the root of a drive (code %1).
russian.DirInvalid=Выберите абсолютный путь к папке, но не корень диска (код %1).
english.DirDrive=Use a local fixed drive with NTFS permissions (code %1).
russian.DirDrive=Нужен локальный постоянный диск с правами NTFS (код %1).
english.DirSystem=Do not install inside a user profile or the Windows folder. Choose Program Files or a safe folder on another drive.
russian.DirSystem=Нельзя устанавливать в профиль пользователя или папку Windows. Выберите Program Files или безопасную папку на другом диске.
english.DirReparse=This path contains a link or junction. Choose a regular folder.
russian.DirReparse=Путь содержит ссылку или точку соединения. Выберите обычную папку.
english.DirWritable=This folder or an ancestor can be changed by standard users. The SYSTEM service would be unsafe there. Choose Program Files or a new folder directly under a drive root.
russian.DirWritable=Эту папку или одну из папок выше могут менять обычные пользователи. Для службы с правами SYSTEM это небезопасно. Выберите Program Files или новую папку прямо в корне диска.
english.DirOccupied=The folder is not empty. Choose an empty or new folder.
russian.DirOccupied=Папка не пустая. Выберите пустую или новую папку.
english.DirUnknown=Could not verify or secure the folder. Choose another folder or check its permissions.
russian.DirUnknown=Не удалось проверить или защитить папку. Выберите другую папку или проверьте права.
english.DirUpgrade=If this is an upgrade of an existing installation, uninstall Rosetun and install it again in a safe folder.
russian.DirUpgrade=Если вы обновляете установленную программу, удалите Rosetun и установите заново в безопасную папку.
english.DirFailed=Installation stopped: %1 %2
russian.DirFailed=Установка прервана: %1 %2

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#BuildDir}\{#GuiExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BuildDir}\{#HelperExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BuildDir}\{#HelperExe}"; DestName: "{#TempHelperExe}"; Flags: dontcopy
Source: "{#BuildDir}\rosetun.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SingBoxDir}\sing-box.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#LicensesDir}\*"; DestDir: "{app}\licenses"; Flags: ignoreversion recursesubdirs

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

var
  InstallHelperExtracted: Boolean;

function InstallDirMessage(Code: Integer): String;
begin
  case Code of
    2: Result := CustomMessage('DirInvalid');
    3, 4: Result := FmtMessage(CustomMessage('DirDrive'), [IntToStr(Code)]);
    5: Result := CustomMessage('DirSystem');
    6: Result := CustomMessage('DirReparse');
    7, 8: Result := CustomMessage('DirWritable');
    9: Result := CustomMessage('DirOccupied');
  else
    Result := CustomMessage('DirUnknown');
  end;
  if Code = 2 then
    Result := FmtMessage(Result, [IntToStr(Code)]);
end;

function RunInstallHelper(const Mode, Dir: String): Integer;
var
  Output: TExecOutput;
  I: Integer;
  NormalDir: String;
begin
  Result := 10;
  if Pos('"', Dir) > 0 then
  begin
    Result := 2;
    Exit;
  end;
  NormalDir := Dir;
  while (Length(NormalDir) > 3) and (NormalDir[Length(NormalDir)] = '\') do
    Delete(NormalDir, Length(NormalDir), 1);
  try
    if not InstallHelperExtracted then
    begin
      ExtractTemporaryFile('{#TempHelperExe}');
      InstallHelperExtracted := True;
    end;
    if ExecAndCaptureOutput(ExpandConstant('{tmp}\{#TempHelperExe}'),
      Mode + ' "' + NormalDir + '"', '', SW_HIDE, ewWaitUntilTerminated, Result, Output) then
    begin
      for I := 0 to GetArrayLength(Output.StdOut) - 1 do
        Log(Output.StdOut[I]);
      for I := 0 to GetArrayLength(Output.StdErr) - 1 do
        Log(Output.StdErr[I]);
      if Output.Error then
      begin
        Log('Install helper output capture failed');
        Result := 10;
      end;
    end
    else
      Result := 10;
  except
    Log('Install directory helper failed: ' + GetExceptionMessage());
    Result := 10;
  end;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  Code: Integer;
begin
  Result := True;
  if CurPageID = wpSelectDir then
  begin
    Code := RunInstallHelper('--verify-install-dir', WizardDirValue());
    if Code <> 0 then
    begin
      MsgBox(InstallDirMessage(Code), mbError, MB_OK);
      Result := False;
    end;
  end;
end;

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
  if CurStep = ssInstall then
  begin
    ResultCode := RunInstallHelper('--verify-install-dir', WizardDirValue());
    if ResultCode = 0 then
      ResultCode := RunInstallHelper('--secure-install-dir', WizardDirValue());
    if ResultCode <> 0 then
    begin
      SuppressibleMsgBox(FmtMessage(CustomMessage('DirFailed'), [InstallDirMessage(ResultCode),
        CustomMessage('DirUpgrade')]), mbError, MB_OK, IDOK);
      Log('Install directory validation failed with exit code ' + IntToStr(ResultCode));
      Abort;
    end;
  end;
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
