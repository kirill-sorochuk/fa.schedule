#!/usr/bin/env python3
"""
Диагностический скрипт для проверки работы LK и связанных компонентов fa.schedule
Проверяет:
1. Доступность эндпоинтов
2. Корректность JSON-ответов
3. Скорость загрузки
4. Структуру данных
"""

import asyncio
import aiohttp
import json
import sys
from datetime import datetime
from typing import Optional, Dict, Any

# Цвета для вывода
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_status(status: str, message: str):
    color = {
        'OK': Colors.GREEN,
        'ERROR': Colors.RED,
        'WARN': Colors.YELLOW,
        'INFO': Colors.BLUE
    }.get(status, Colors.RESET)
    print(f"{color}{status}{Colors.RESET}: {message}")

async def check_endpoint(session: aiohttp.ClientSession, name: str, url: str, 
                         expected_status: int = 200, 
                         headers: Optional[Dict[str, str]] = None,
                         method: str = 'GET',
                         json_data: Optional[Dict] = None) -> Dict[str, Any]:
    """Проверка одного эндпоинта"""
    result = {
        'name': name,
        'url': url,
        'status': 'UNKNOWN',
        'http_status': None,
        'response_time': None,
        'error': None,
        'data_valid': None
    }
    
    try:
        start_time = datetime.now()
        
        if method == 'GET':
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as response:
                result['http_status'] = response.status
                data = await response.text()
        elif method == 'POST':
            async with session.post(url, headers=headers, json=json_data, timeout=aiohttp.ClientTimeout(total=10)) as response:
                result['http_status'] = response.status
                data = await response.text()
        
        end_time = datetime.now()
        result['response_time'] = (end_time - start_time).total_seconds()
        
        # Проверка статуса
        if result['http_status'] != expected_status:
            result['status'] = 'ERROR'
            result['error'] = f"HTTP статус {result['http_status']} вместо {expected_status}"
            return result
        
        # Попытка распарсить JSON
        try:
            json_data = json.loads(data)
            result['data_valid'] = True
            result['status'] = 'OK'
            
            # Проверка структуры для разных эндпоинтов
            if 'notification' in url:
                if 'items' not in json_data:
                    result['status'] = 'WARN'
                    result['error'] = 'Отсутствует поле items в ответе'
            elif 'rating' in url:
                if 'items' not in json_data:
                    result['status'] = 'WARN'
                    result['error'] = 'Отсутствует поле items в ответе'
            elif 'service-ticket' in url:
                if 'items' not in json_data:
                    result['status'] = 'WARN'
                    result['error'] = 'Отсутствует поле items в ответе'
                    
        except json.JSONDecodeError:
            result['data_valid'] = False
            result['status'] = 'WARN'
            result['error'] = 'Ответ не является валидным JSON'
            
    except asyncio.TimeoutError:
        result['status'] = 'ERROR'
        result['error'] = 'Превышено время ожидания (10с)'
    except Exception as e:
        result['status'] = 'ERROR'
        result['error'] = str(e)
    
    return result

async def main():
    print(f"\n{Colors.BOLD}=== Диагностика fa.schedule ==={Colors.RESET}")
    print(f"Время запуска: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # Список эндпоинтов для проверки
    endpoints = [
        {
            'name': 'Уведомления',
            'url': 'https://lk.fa.ru/services/api/profile/v1/notification?page=1&pageSize=10',
            'headers': {'X-Timezone-IANA': 'Europe/Moscow'}
        },
        {
            'name': 'Рейтинг (весна 2026)',
            'url': 'https://lk.fa.ru/services/api/profile/v1/my-student-rating?page=1&pageSize=10&semester=spring-2026&sort=modifiedAt-',
            'headers': {'X-Timezone-IANA': 'Europe/Moscow'}
        },
        {
            'name': 'Обращения/Заказы',
            'url': 'https://lk.fa.ru/services/api/otrs/v2/servicing/service-ticket?page=1&pageSize=20',
            'headers': {'X-Timezone-IANA': 'Europe/Moscow'}
        },
        {
            'name': 'Меню',
            'url': 'https://lk.fa.ru/api/menu/?lang=ru',
            'headers': {}
        },
        {
            'name': 'Данные пользователя',
            'url': 'https://lk.fa.ru/api/user-data/',
            'headers': {}
        },
        {
            'name': 'Проверка сессии',
            'url': 'https://lk.fa.ru/elk/api/auth/session',
            'headers': {}
        },
        # Bitrix эндпоинты (требуют SSO cookies)
        {
            'name': 'VKR Bootstrap',
            'url': 'https://org.fa.ru/bitrix/vuz/api/vkr/bootstrap',
            'headers': {
                'App-Version': '8.135.3',
                'App-Key': 'browser-bitrix',
                'App-Locale': 'ru'
            }
        }
    ]
    
    results = []
    
    # Создаем сессию без cookies (для публичных эндпоинтов)
    # Для авторизованных нужна будет сессия с cookies
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        for ep in endpoints:
            task = check_endpoint(
                session=session,
                name=ep['name'],
                url=ep['url'],
                headers=ep.get('headers', {})
            )
            tasks.append(task)
        
        # Выполняем все запросы параллельно
        results = await asyncio.gather(*tasks)
    
    # Вывод результатов
    print(f"\n{Colors.BOLD}=== Результаты ==={Colors.RESET}\n")
    
    ok_count = 0
    warn_count = 0
    error_count = 0
    
    for r in results:
        status_color = {
            'OK': Colors.GREEN,
            'WARN': Colors.YELLOW,
            'ERROR': Colors.RED
        }.get(r['status'], Colors.RESET)
        
        print(f"{status_color}{r['status']}{Colors.RESET} | {r['name']}")
        print(f"       URL: {r['url']}")
        
        if r['response_time']:
            time_str = f"{r['response_time']*1000:.0f}ms"
            if r['response_time'] < 0.5:
                time_color = Colors.GREEN
            elif r['response_time'] < 1.0:
                time_color = Colors.YELLOW
            else:
                time_color = Colors.RED
            print(f"       Время: {time_color}{time_str}{Colors.RESET}")
        
        if r['http_status']:
            print(f"       HTTP: {r['http_status']}")
        
        if r['data_valid'] is not None:
            valid_str = "✓ Валидный JSON" if r['data_valid'] else "✗ Не JSON"
            print(f"       Данные: {valid_str}")
        
        if r['error']:
            print(f"       Ошибка: {Colors.RED}{r['error']}{Colors.RESET}")
        
        if r['status'] == 'OK':
            ok_count += 1
        elif r['status'] == 'WARN':
            warn_count += 1
        else:
            error_count += 1
        
        print()
    
    # Итоги
    print(f"\n{Colors.BOLD}=== Итого ==={Colors.RESET}")
    print(f"{Colors.GREEN}OK: {ok_count}{Colors.RESET} | " +
          f"{Colors.YELLOW}WARN: {warn_count}{Colors.RESET} | " +
          f"{Colors.RED}ERROR: {error_count}{Colors.RESET}")
    
    if error_count > 0:
        print(f"\n{Colors.RED}⚠ Обнаружены проблемы с доступностью эндпоинтов!{Colors.RESET}")
        print("Возможные причины:")
        print("  - Требуется авторизация (cookies/Bearer токен)")
        print("  - Эндпоинт недоступен извне корпоративной сети")
        print("  - Изменилась структура API")
        return 1
    else:
        print(f"\n{Colors.GREEN}✓ Все эндпоинты доступны!{Colors.RESET}")
        return 0

if __name__ == '__main__':
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
