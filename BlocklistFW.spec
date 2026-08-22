# -*- mode: python ; coding: utf-8 -*-

a = Analysis(
    ['run_ui.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('resources/icons/app_icon.ico', 'resources/icons'),
        ('threat_intelligence.db', '.'),
    ],
    hiddenimports=['psutil', 'win32com', 'win32com.client'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='BlocklistFW',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='resources/icons/app_icon.ico',
    # Кладём все файлы в ту же папку, что и exe, без вложенной папки _internal
    contents_directory='.',
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='BlocklistFW',
)