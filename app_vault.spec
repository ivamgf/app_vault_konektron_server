# -*- mode: python ; coding: utf-8 -*-
# Configuração do PyInstaller. Gere com:  python -m PyInstaller --noconfirm --clean app_vault.spec
import os
import sys

sys.path.insert(0, SPECPATH)
from version import APP_NAME, __version__  # noqa: E402
from PyInstaller.utils.win32.versioninfo import (  # noqa: E402
    FixedFileInfo, StringFileInfo, StringStruct, StringTable, VarFileInfo, VarStruct,
    VSVersionInfo)

EXE_NAME = "AppVaultProtection"
_v = tuple(int(x) for x in __version__.split(".")) + (0,)

version_info = VSVersionInfo(
    ffi=FixedFileInfo(filevers=_v, prodvers=_v),
    kids=[
        StringFileInfo([StringTable("041604B0", [   # pt-BR, Unicode
            StringStruct("FileDescription", APP_NAME),
            StringStruct("ProductName", APP_NAME),
            StringStruct("FileVersion", __version__),
            StringStruct("ProductVersion", __version__),
            StringStruct("InternalName", EXE_NAME),
            StringStruct("OriginalFilename", EXE_NAME + ".exe"),
        ])]),
        VarFileInfo([VarStruct("Translation", [0x0416, 1200])]),
    ],
)

a = Analysis(
    ["app.py"],
    pathex=[SPECPATH],
    datas=[(os.path.join("assets", "app.ico"), "assets"),
           (os.path.join("assets", "app.png"), "assets")],
    excludes=["tests"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name=EXE_NAME,
    console=False,              # app de janela, sem console
    icon=os.path.join("assets", "app.ico"),
    version=version_info,
    upx=False,                  # UPX costuma gerar falso positivo em antivírus
)
coll = COLLECT(exe, a.binaries, a.datas, name=EXE_NAME, upx=False)
