; Instalador do App Vault Protection (Inno Setup 6).
; Gere com:  ISCC.exe /DAppVersion=1.0.0 installer\app_vault.iss   (ou use build.ps1)

#define AppName "App Vault Protection"
#define AppExe "AppVaultProtection.exe"
#define AppURL "https://github.com/ivamgf/app_vault_konektron_server"
#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
; AppId identifica o programa entre versões: não altere.
AppId={{6F1C2B9E-4A7D-4E3B-9C55-2D8A41E7B0F3}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher=Konektron
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
AppUpdatesURL={#AppURL}/releases/latest
VersionInfoVersion={#AppVersion}
; Instalação por usuário, sem privilégios de administrador:
; vai para %LOCALAPPDATA%\Programs\App Vault Protection
PrivilegesRequired=lowest
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\dist\installer
OutputBaseFilename=AppVaultProtection-Setup-{#AppVersion}
SetupIconFile=..\assets\app.ico
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
; Fecha o app aberto antes de atualizar.
CloseApplications=yes

[Languages]
Name: "brazilianportuguese"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[InstallDelete]
; Remove arquivos de versões anteriores do programa (nunca os dados do usuário).
Type: filesandordirs; Name: "{app}\_internal"

[Files]
Source: "..\dist\AppVaultProtection\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExe}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent

; Os cofres ficam em %LOCALAPPDATA%\AppVaultProtection (fora da pasta do programa)
; e NÃO são apagados na desinstalação.
