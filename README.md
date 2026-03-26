# APK Helper V59

A GUI tool (customtkinter) for batch analysis of Android APK files.

## Features

* System-wide APK scan with include/exclude path management
* Duplicate detection and batch selection
* Forensic pipeline: decompile (apktool), code harvest, image harvest, report generation

## Quick Start

```bash
pip install -r requirements.txt
# apktool.jar must be present in the same directory
python apk_master.py
```

## Output structure (per APK)

```
MY_APP_LIBRARY/<pkg>_v<ver>/
├── COMPARE_IMAGES/           # Semantically grouped images
│   ├── Buttons/
│   │   └── Button_Ok/
│   │       ├── hdpi.png
│   │       └── xhdpi.png
│   ├── Icons/
│   └── ...
├── _CODE/                    # Core app smali
├── _SDK/                     # Third-party SDK smali
├── _THREATS/                 # Smali files that matched threat signatures
└── Overview.md               # Quick-read report with permission classification
```

## Overview.md sections

| Section | Content |
|---|---|
| **Einstieg** | Detected entry-point classes (MainActivity, onCreate, Service…) |
| **Berechtigungen** | ⚠️ Auffällig / ℹ️ Beachtenswert / ✅ Unkritisch |
| **Netzwerk** | Deduplicated domains; 📢 Ads/Tracking flagged separately |
| **Threat-Hinweise** | Count of smali files matching threat signatures |

## Dependencies

* [customtkinter](https://github.com/TomSchimansky/CustomTkinter) – GUI framework
* [psutil](https://github.com/giampaolo/psutil) – process management
* [androguard](https://github.com/androguard/androguard) – APK metadata (optional, falls back to byte scan)
* [apktool](https://apktool.org/) – decompile/rebuild (must be in PATH or same directory)