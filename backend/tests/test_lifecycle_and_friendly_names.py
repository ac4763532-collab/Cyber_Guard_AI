"""
Unit tests for human-friendly plain English app names, folder locations,
and software lifecycle tracking in CyberGuard AI.
"""

import pytest
from app.services.windows_event_explainer import (
    resolve_friendly_app_name,
    explain_folder_path,
    get_friendly_event_summary,
    KNOWN_APPS,
)


def test_resolve_friendly_app_names():
    chrome_name, chrome_type, chrome_icon = resolve_friendly_app_name("chrome.exe")
    assert chrome_name == "Google Chrome"
    assert chrome_type == "desktop_app"
    assert chrome_icon == "🌐"

    vscode_name, vscode_type, vscode_icon = resolve_friendly_app_name("C:\\Users\\Abhi chavan\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe")
    assert vscode_name == "Visual Studio Code"
    assert vscode_type == "desktop_app"
    assert vscode_icon == "📝"

    pg_name, pg_type, pg_icon = resolve_friendly_app_name("postgres.exe")
    assert pg_name == "PostgreSQL Database Engine"
    assert pg_type == "database"
    assert pg_icon == "🐘"

    audio_name, audio_type, _ = resolve_friendly_app_name("audiodg.exe")
    assert audio_name == "Windows Audio Isolation Service"
    assert audio_type == "background_system"

    svc_name, svc_type, _ = resolve_friendly_app_name("svchost.exe")
    assert svc_name == "Windows Service Host"
    assert svc_type == "background_system"

    # Clean fallback for unknown custom apps
    custom_name, custom_type, _ = resolve_friendly_app_name("my_custom_tool.exe")
    assert custom_name == "My Custom Tool"
    assert custom_type == "desktop_app"

    # RuntimeBroker with path should resolve to clean product name WITHOUT paths
    rt_name, rt_type, _ = resolve_friendly_app_name("C:\\Program Files\\Runtimebroker.exe")
    assert rt_name == "Windows Runtime Broker"
    assert rt_type == "background_system"

    # Notepad with or without path
    np_name, np_type, _ = resolve_friendly_app_name("C:\\Windows\\System32\\notepad.exe")
    assert np_name == "Notepad"
    assert np_type == "desktop_app"


def test_explain_folder_paths():
    assert explain_folder_path("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe") == "Program Files (Installed Software)"
    assert explain_folder_path("C:\\Program Files (x86)\\Steam\\steam.exe") == "Program Files (Installed Software)"
    assert explain_folder_path("C:\\Users\\Abhi chavan\\Downloads\\installer.exe") == "Downloads folder"
    assert explain_folder_path("C:\\Users\\Abhi chavan\\Desktop\\project\\app.exe") == "Desktop"
    assert explain_folder_path("C:\\Users\\Abhi chavan\\Documents\\file.exe") == "Documents folder"
    assert explain_folder_path("C:\\Windows\\System32\\svchost.exe") == "Windows System folder"
    assert explain_folder_path("C:\\Users\\Abhi chavan\\AppData\\Local\\Temp\\update.exe") == "Temporary Files folder"


def test_friendly_event_summaries_lifecycle():
    # 1. App Opened
    ev_opened = get_friendly_event_summary(
        event_type="windows.app.opened",
        raw_payload={"process_name": "chrome.exe", "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"},
        username="Abhi chavan",
        hostname="DESKTOP-4DAGSCE",
        process_name="chrome.exe",
    )
    assert ev_opened["title"] == "Google Chrome Opened"
    assert ev_opened["badge_label"] == "App Opened"
    assert "Google Chrome was opened on DESKTOP-4DAGSCE by Abhi chavan in Program Files (Installed Software)" in ev_opened["friendly_details"]

    # 2. App Closed
    ev_closed = get_friendly_event_summary(
        event_type="windows.app.closed",
        raw_payload={"process_name": "chrome.exe"},
        username="Abhi chavan",
        hostname="DESKTOP-4DAGSCE",
        process_name="chrome.exe",
    )
    assert ev_closed["title"] == "Google Chrome Closed"
    assert ev_closed["badge_label"] == "App Closed"
    assert "Google Chrome was closed on DESKTOP-4DAGSCE" in ev_closed["friendly_details"]

    # 3. Wrong Password
    ev_wrong_pwd = get_friendly_event_summary(
        event_type="windows.security.4625",
        raw_payload={"TargetUserName": "Abhi chavan", "Status": "0xC000006D", "SubStatus": "0xC000006A"},
        username="Abhi chavan",
        hostname="DESKTOP-4DAGSCE",
    )
    assert "Wrong Password" in ev_wrong_pwd["title"]
    assert ev_wrong_pwd["badge_label"] == "Wrong Password"
    assert "Wrong password entered" in ev_wrong_pwd["friendly_details"]

    # 4. Software Installed (MSI)
    ev_installed = get_friendly_event_summary(
        event_type="windows.software.installed",
        raw_payload={"ProductName": "CyberGuard Collector", "Status": "0"},
        username="SYSTEM",
        hostname="DESKTOP-4DAGSCE",
    )
    assert ev_installed["badge_label"] == "Software Installed"
    assert "installed" in ev_installed["friendly_details"]

    # 5. Software Uninstalled (MSI)
    ev_removed = get_friendly_event_summary(
        event_type="windows.software.uninstalled",
        raw_payload={"ProductName": "Old Tool"},
        username="SYSTEM",
        hostname="DESKTOP-4DAGSCE",
    )
    assert ev_removed["badge_label"] == "Software Removed"
    assert "uninstalled" in ev_removed["friendly_details"]

    # 6. Laptop Locked & Unlocked
    ev_locked = get_friendly_event_summary(
        event_type="windows.workstation.locked",
        username="Abhi chavan",
        hostname="DESKTOP-4DAGSCE",
    )
    assert ev_locked["title"] == "Laptop Screen Locked"
    assert ev_locked["badge_label"] == "Laptop Locked"

    ev_unlocked = get_friendly_event_summary(
        event_type="windows.workstation.unlocked",
        username="Abhi chavan",
        hostname="DESKTOP-4DAGSCE",
    )
    assert ev_unlocked["title"] == "Laptop Screen Unlocked"
    assert ev_unlocked["badge_label"] == "Laptop Unlocked"

    # 7. Notepad Opened & Closed (real desktop app)
    ev_np_opened = get_friendly_event_summary(
        event_type="windows.app.opened",
        process_name="notepad.exe",
        hostname="DESKTOP-4DAGSCE",
        username="Abhi chavan",
    )
    assert ev_np_opened["title"] == "Notepad Opened"
    assert ev_np_opened["badge_label"] == "App Opened"

    ev_np_closed = get_friendly_event_summary(
        event_type="windows.app.closed",
        process_name="notepad.exe",
        hostname="DESKTOP-4DAGSCE",
        username="Abhi chavan",
    )
    assert ev_np_closed["title"] == "Notepad Closed"
    assert ev_np_closed["badge_label"] == "App Closed"

    # 8. Background Daemons: NEVER show path in title and NEVER show "Svchost Opened"
    ev_rt_closed = get_friendly_event_summary(
        event_type="windows.app.closed",
        raw_payload={"ProcessName": "C:\\Program Files\\Runtimebroker.exe"},
        process_name="C:\\Program Files\\Runtimebroker.exe",
        hostname="DESKTOP-4DAGSCE",
    )
    assert ev_rt_closed["title"] == "Windows Runtime Broker Stopped"
    assert "Program Files" not in ev_rt_closed["title"]

    ev_svc_opened = get_friendly_event_summary(
        event_type="windows.app.opened",
        process_name="svchost.exe",
        hostname="DESKTOP-4DAGSCE",
    )
    assert ev_svc_opened["title"] == "Windows Service Host Started"
    assert ev_svc_opened["title"] != "Svchost Opened"
