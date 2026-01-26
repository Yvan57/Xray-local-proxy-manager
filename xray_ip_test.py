#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Xray IP Diagnostic Tool v1.0
Минималистичный скрипт для диагностики проблем с получением IP через прокси
"""

import os
import sys
import json
import base64
import subprocess
import time
import requests
import platform
import ctypes
from urllib.parse import urlparse, parse_qs, unquote

# Инициализация цветов для Windows
def init_colors():
    if platform.system() == "Windows":
        try:
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except:
            pass

init_colors()

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

def log(msg, color=Colors.ENDC):
    """Логирование с цветом"""
    print(f"{color}{msg}{Colors.ENDC}")

def parse_share_link(link):
    """Парсер VLESS с полной поддержкой streamSettings"""
    try:
        parsed = urlparse(link.strip())
        protocol = parsed.scheme.lower()
        
        if protocol == "vless":
            uuid = parsed.username or parsed.netloc.split('@')[0]
            host_port = parsed.netloc.split('@')[1] if '@' in parsed.netloc else parsed.netloc
            host = host_port.split(':')[0]
            port = int(host_port.split(':')[1]) if ':' in host_port else 443
            params = parse_qs(parsed.query)
            
            # Основные параметры
            network = params.get("type", ["tcp"])[0]
            security = params.get("security", ["none"])[0]
            
            # Построение streamSettings
            stream_settings = {
                "network": network
            }
            
            # TLS настройки
            if security == "tls":
                stream_settings["security"] = "tls"
                stream_settings["tlsSettings"] = {
                    "allowInsecure": params.get("allowInsecure", ["0"])[0] == "1",
                    "serverName": params.get("sni", [""])[0] or host
                }
                if params.get("alpn"):
                    stream_settings["tlsSettings"]["alpn"] = params.get("alpn")[0].split(",")
                if params.get("fp"):
                    stream_settings["tlsSettings"]["fingerprint"] = params.get("fp")[0]
            
            # Reality настройки
            elif security == "reality":
                stream_settings["security"] = "reality"
                stream_settings["realitySettings"] = {
                    "serverName": params.get("sni", [""])[0] or host,
                    "publicKey": params.get("pbk", [""])[0],
                    "shortId": params.get("sid", [""])[0],
                    "fingerprint": params.get("fp", ["chrome"])[0]
                }
            
            # WS настройки
            if network == "ws":
                stream_settings["wsSettings"] = {
                    "path": params.get("path", ["/"])[0],
                    "headers": {}
                }
                if params.get("host"):
                    stream_settings["wsSettings"]["headers"]["Host"] = params.get("host")[0]
            
            # gRPC настройки
            elif network == "grpc":
                stream_settings["grpcSettings"] = {
                    "serviceName": params.get("serviceName", [""])[0]
                }
            
            # HTTP/2 настройки
            elif network == "h2":
                stream_settings["httpSettings"] = {
                    "path": params.get("path", ["/"])[0],
                    "host": [params.get("host", [""])[0]] if params.get("host") else []
                }
            
            # VLESS outbound конфиг
            outbound = {
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": host,
                        "port": port,
                        "users": [{
                            "id": uuid,
                            "encryption": params.get("encryption", ["none"])[0],
                            "flow": params.get("flow", [""])[0],
                            "level": 0
                        }]
                    }]
                },
                "streamSettings": stream_settings
            }
            
            return outbound
        else:
            raise ValueError(f"Только VLESS поддерживается в диагностике. Ты указал: {protocol}")
    except Exception as e:
        raise ValueError(f"Ошибка парсинга: {e}")

def main():
    print(f"\n{Colors.BLUE}{'━'*50}{Colors.ENDC}")
    print(f" {Colors.BOLD}{Colors.CYAN}⚡ XRAY IP DIAGNOSTIC TOOL v1.0{Colors.ENDC}")
    print(f"{Colors.BLUE}{'━'*50}{Colors.ENDC}\n")
    
    # Ввод данных
    port_str = input(f"{Colors.YELLOW}Введите номер тестового порта (1024-65535, Enter=9999): {Colors.ENDC}").strip()
    port = int(port_str) if port_str else 9999
    
    if not (1024 <= port <= 65535):
        log("❌ Некорректный номер порта", Colors.RED)
        return
    
    log(f"\n📝 Введите Share Link (VLESS):", Colors.CYAN)
    link = input().strip()
    
    if not link:
        log("❌ Link не указан", Colors.RED)
        return
    
    # Парсинг
    log(f"\n1️⃣  Парсинг share link...", Colors.YELLOW)
    try:
        outbound = parse_share_link(link)
        log(f"✔ Успешно", Colors.GREEN)
        log(f"   Протокол: VLESS", Colors.CYAN)
        log(f"   Сервер: {outbound['settings']['vnext'][0]['address']}:{outbound['settings']['vnext'][0]['port']}", Colors.CYAN)
    except Exception as e:
        log(f"❌ Ошибка: {e}", Colors.RED)
        return
    
    # Поиск xray
    log(f"\n2️⃣  Поиск xray.exe...", Colors.YELLOW)
    candidates = ["xray.exe", "v2ray.exe", "./xray.exe", "./v2ray.exe"]
    xray_exe = None
    for exe in candidates:
        if os.path.exists(exe):
            xray_exe = exe
            break
    
    if not xray_exe:
        log(f"❌ xray.exe не найден в текущей папке", Colors.RED)
        custom = input(f"{Colors.YELLOW}Введите полный путь: {Colors.ENDC}").strip()
        if os.path.exists(custom):
            xray_exe = custom
        else:
            log(f"❌ Файл не найден: {custom}", Colors.RED)
            return
    
    log(f"✔ Найден: {xray_exe}", Colors.GREEN)
    
    # Создание конфига
    log(f"\n3️⃣  Создание конфига...", Colors.YELLOW)
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "port": port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True}
        }],
        "outbounds": [outbound]
    }
    cfg_file = f"xray_test_{port}.json"
    try:
        with open(cfg_file, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        log(f"✔ Конфиг создан: {cfg_file}", Colors.GREEN)
        
        # Проверка что конфиг валидный JSON
        with open(cfg_file, 'r', encoding='utf-8') as f:
            test_load = json.load(f)
        log(f"✔ Конфиг валиден", Colors.GREEN)
    except Exception as e:
        log(f"❌ Ошибка создания конфига: {e}", Colors.RED)
        return
    
    # Запуск xray
    log(f"\n4️⃣  Запуск xray на порту {port}...", Colors.YELLOW)
    try:
        process = subprocess.Popen(
            [xray_exe, "run", "-config", cfg_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        )
        time.sleep(2)
        
        if process.poll() is not None:
            # Процесс уже завершился - ошибка
            stdout = process.stdout.read().decode('utf-8', errors='ignore')
            stderr = process.stderr.read().decode('utf-8', errors='ignore')
            
            log(f"❌ Xray не запустился", Colors.RED)
            
            if stderr:
                log(f"   STDERR: {stderr[:300]}", Colors.DIM)
            if stdout:
                log(f"   STDOUT: {stdout[:300]}", Colors.DIM)
            
            # Проверим конфиг вручную
            log(f"\n   Попытка запустить xray напрямую для отладки...", Colors.YELLOW)
            try:
                result = subprocess.run(
                    [xray_exe, "run", "-config", cfg_file],
                    capture_output=True,
                    text=True,
                    timeout=3
                )
                log(f"   Return code: {result.returncode}", Colors.DIM)
                if result.stderr:
                    log(f"   Error output: {result.stderr[:500]}", Colors.DIM)
            except subprocess.TimeoutExpired:
                log(f"   Timeout - значит xray работает!", Colors.GREEN)
            except Exception as e:
                log(f"   Ошибка отладки: {e}", Colors.DIM)
            
            return
        
        log(f"✔ Xray запущен (PID: {process.pid})", Colors.GREEN)
    except Exception as e:
        log(f"❌ Ошибка запуска: {e}", Colors.RED)
        return
    
    # Тестирование IP
    log(f"\n5️⃣  Проверка IP через 2 API...", Colors.YELLOW)
    
    # Проверим доступность pysocks
    try:
        import socks
        HAS_SOCKS = True
    except ImportError:
        HAS_SOCKS = False
        log(f"\n⚠️  pysocks не установлен", Colors.YELLOW)
        log(f"   Установи: {Colors.CYAN}pip install pysocks{Colors.ENDC}", Colors.YELLOW)
        log(f"   Пока пробуем напрямую...\n", Colors.DIM)
    
    proxies = {
        "http": f"socks5://127.0.0.1:{port}",
        "https": f"socks5://127.0.0.1:{port}"
    } if HAS_SOCKS else {}
    
    apis = [
        ("https://api.ip.sb/geoip", "api.ip.sb"),
        ("https://api-ipv4.ip.sb/geoip", "api-ipv4.ip.sb"),
    ]
    
    success = False
    for api_url, api_name in apis:
        log(f"\n   Попытка {api_name}...", Colors.CYAN)
        try:
            log(f"   → Отправка запроса...", Colors.DIM)
            
            if HAS_SOCKS:
                r = requests.get(api_url, proxies=proxies, timeout=10)
            else:
                # Без pysocks - просто пробуем прямой запрос
                r = requests.get(api_url, timeout=10)
            
            log(f"   → Статус: {r.status_code}", Colors.DIM)
            
            if r.status_code == 200:
                data = r.json()
                log(f"   → JSON получен", Colors.DIM)
                
                ip = data.get('ip', 'N/A')
                country = data.get('country', 'N/A')
                city = data.get('city', 'N/A')
                isp = data.get('isp', data.get('organization', 'N/A'))
                timezone = data.get('timezone', 'N/A')
                
                log(f"\n✔ {Colors.BOLD}УСПЕХ!{Colors.ENDC}", Colors.GREEN)
                log(f"   IP: {Colors.CYAN}{ip}{Colors.ENDC}", Colors.GREEN)
                log(f"   Город: {city}, Страна: {country}", Colors.GREEN)
                log(f"   ISP: {isp}", Colors.GREEN)
                log(f"   Timezone: {timezone}", Colors.GREEN)
                
                if not HAS_SOCKS:
                    log(f"\n⚠️  Это прямой запрос, не через прокси", Colors.YELLOW)
                    log(f"   Для проверки IP через прокси установи: {Colors.CYAN}pip install pysocks{Colors.ENDC}", Colors.DIM)
                
                success = True
                break
            else:
                log(f"   ❌ HTTP {r.status_code}", Colors.RED)
                log(f"   Ответ: {r.text[:100]}", Colors.DIM)
        
        except requests.exceptions.ProxyError:
            log(f"   ❌ ОШИБКА ПРОКСИ - проверь конфиг VLESS", Colors.RED)
            log(f"   Убедись что:", Colors.YELLOW)
            log(f"      • UUID правильный", Colors.DIM)
            log(f"      • Адрес сервера корректный", Colors.DIM)
            log(f"      • Порт открыт на сервере", Colors.DIM)
        except requests.exceptions.ConnectTimeout:
            log(f"   ❌ TIMEOUT - сервер не отвечает", Colors.RED)
            log(f"   Проверь:", Colors.YELLOW)
            log(f"      • Адрес хоста: правильный ли?", Colors.DIM)
            log(f"      • Интернет соединение активно?", Colors.DIM)
        except requests.exceptions.ConnectionError as e:
            log(f"   ❌ ОШИБКА СОЕДИНЕНИЯ", Colors.RED)
            log(f"   Детали: {str(e)[:100]}", Colors.DIM)
        except Exception as e:
            log(f"   ❌ НЕИЗВЕСТНАЯ ОШИБКА", Colors.RED)
            log(f"   Тип: {type(e).__name__}", Colors.DIM)
            log(f"   Сообщение: {str(e)[:100]}", Colors.DIM)
        
        time.sleep(1)
    
    # Очистка
    log(f"\n6️⃣  Остановка xray...", Colors.YELLOW)
    try:
        process.terminate()
        process.wait(timeout=2)
        log(f"✔ Xray остановлен", Colors.GREEN)
    except:
        process.kill()
        log(f"✔ Xray принудительно завершен", Colors.GREEN)
    
    # Удаление конфига
    try:
        os.remove(cfg_file)
    except:
        pass
    
    # Итоги
    print(f"\n{Colors.BLUE}{'━'*50}{Colors.ENDC}")
    if success:
        log(f"✔ ДИАГНОСТИКА УСПЕШНА", Colors.GREEN)
    else:
        log(f"❌ ДИАГНОСТИКА ВЫЯВИЛА ПРОБЛЕМЫ", Colors.RED)
        log(f"\nВероятные причины:", Colors.YELLOW)
        log(f"  1. Неверный VLESS link", Colors.DIM)
        log(f"  2. Сервер недоступен или перегружен", Colors.DIM)
        log(f"  3. Конфиг VLESS несовместим с xray", Colors.DIM)
        log(f"  4. Сайт api.ip.sb недоступен через прокси", Colors.DIM)
    print(f"{Colors.BLUE}{'━'*50}{Colors.ENDC}\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log(f"\n\n✔ Отменено пользователем", Colors.GREEN)
        sys.exit(0)
    except Exception as e:
        log(f"\n❌ Критическая ошибка: {e}", Colors.RED)
        sys.exit(1)