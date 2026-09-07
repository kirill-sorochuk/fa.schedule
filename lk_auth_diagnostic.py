#!/usr/bin/env python3
"""
Диагностический скрипт авторизации ЛК ФУ (v9).
Полный цикл: NextAuth signin -> Keycloak OAuth2 -> callback -> сессия -> SSO -> org.fa.ru

Использование:
  python3 lk_auth_diagnostic.py <логин> <пароль>

Изменения v9 (КЛЮЧЕВОЕ ОТКРЫТИЕ из инспекции sso-init.php):
  /local/auth/sso-init.php — это HTML с JS, который делает:
    fetch('/bitrix/vuz/sso/link?backurl=%2F', {credentials: 'include'})
    .then(r => r.json())
    .then(data => { window.location.href = data.auth_url; })

  /bitrix/vuz/sso/link возвращает JSON:
    {"auth_url": "https://auth.fa.ru/realms/elk/protocol/openid-connect/auth
                 ?client_id=orgfaru-client
                 &redirect_uri=https://org.fa.ru/bitrix/vuz/sso/callback
                 &response_type=code&scope=openid profile email&state=XXX"}

  Реальный client_id для org.fa.ru = 'orgfaru-client' (не elk-front!).
  redirect_uri = https://org.fa.ru/bitrix/vuz/sso/callback

  v9: step5b полностью переписан — воспроизводит JS-поведение:
    1) GET /                                      (PHPSESSID)
    2) GET /bitrix/vuz/sso/link?backurl=%2F       (auth_url + vuzportalfinun_session)
    3) GET auth_url                               (Keycloak SSO -> 302 с code)
    4) GET /bitrix/vuz/sso/callback?code=XXX      (Bitrix создаёт BX_ORG_FA_RU_*)
    5) GET /app/profile/home                      (догружаем метаданные)

  После этого запросы к /bitrix/vuz/api/* работают на cookies (как браузер).

Изменения v8:
  - step5b GET / с allow_redirects=True (но не сработало из-за JS-редиректа)
  - step6: стратегия A — cookies-only без JWT

Изменения v7:
  - Шаг 5c-2: redirect chain (но остановился на sso-init.php)

Изменения v6:
  - Шаг 5c/5d: поиск client_id

Изменения v5:
  - Фильтры cookies, 6 стратегий auth
"""

import sys
import time
import json
import re
import hashlib
import base64
import secrets
import requests
from urllib.parse import urlparse, parse_qs, quote
from datetime import datetime

# ============================================================================
# КОНСТАНТЫ
# ============================================================================
AUTH_BASE = "https://auth.fa.ru"
LK_BASE = "https://lk.fa.ru"
CALLBACK_BASE = f"{LK_BASE}/elk/api/auth/callback/keycloak"
SESSION_URL = f"{LK_BASE}/elk/api/auth/session"
SIGNIN_URL = f"{LK_BASE}/elk/api/auth/signin/keycloak"
CLIENT_ID = "elk-front"

BITRIX_PROFILE_URL = "https://org.fa.ru/bitrix/vuz/api/profile/current"
BITRIX_ORDERS_URL = "https://org.fa.ru/bitrix/vuz/api/orders/"
STUDENT_ID_URL = "https://lk.fa.ru/elk/api/profile/student-id"

# Для SSO-запроса JWT (используем зарегистрированный redirect_uri NextAuth)
# Редиректы блокируются, нам нужен только code из Location header
DIRECT_CALLBACK_URI = CALLBACK_BASE

BITRIX_MARKS_URL = "https://org.fa.ru/bitrix/vuz/api/marks2/"
BITRIX_STUDENT_CARD_URL = "https://org.fa.ru/bitrix/vuz/api/profiles/studentCard/"

# ============================================================================
# УТИЛИТЫ
# ============================================================================

def log(msg, level="INFO"):
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    print(f"[{ts}] [{level}] {msg}")

def log_separator(title=""):
    print(f"\n{'='*60}")
    if title:
        print(f"  {title}")
        print(f"{'='*60}")

def log_cookies(session, label=""):
    cookies = session.cookies
    if not cookies:
        log(f"Куки {label}: (пусто)", "WARN")
        return
    log(f"Куки {label} ({len(cookies)} шт):")
    for c in cookies:
        val = c.value[:50] + "..." if len(c.value) > 50 else c.value
        log(f"  {c.name} = {val}  [domain={c.domain}, path={c.path}]")

def log_headers(response, label=""):
    log(f"Заголовки ответа {label}:")
    for k, v in response.headers.items():
        if k.lower() in ('set-cookie', 'location', 'content-type', 'content-length',
                         'server', 'date', 'x-powered-by', 'cache-control'):
            val = v[:120] + "..." if len(v) > 120 else v
            log(f"  {k}: {val}")

def timed_request(session, method, url, allow_redirects=False, **kwargs):
    """Таймированный запрос. allow_redirects по умолчанию False (как в скрипте v3)."""
    start = time.time()
    try:
        if method == "GET":
            resp = session.get(url, allow_redirects=allow_redirects, **kwargs)
        else:
            resp = session.post(url, allow_redirects=allow_redirects, **kwargs)
        elapsed = time.time() - start
        log(f"  Время ответа: {elapsed:.3f}с")
        return resp, elapsed
    except Exception as e:
        elapsed = time.time() - start
        log(f"  Ошибка запроса ({elapsed:.3f}с): {e}", "ERROR")
        raise

def extract_code(url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    codes = params.get("code", [])
    return codes[0] if codes else None

def extract_csrf_from_cookie(session):
    for c in session.cookies:
        if "csrf" in c.name.lower() and "next-auth" in c.name.lower():
            value = c.value
            for sep in ["%7C", "|"]:
                if sep in value:
                    return value.split(sep)[0]
            return value
    return None

def parse_login_form(html):
    log("Парсинг формы логина...")
    action_match = re.search(r'<form[^>]+action="([^"]+)"', html)
    action = action_match.group(1).replace("&amp;", "&") if action_match else None
    log(f"Form action: {action}")
    hidden_fields = {}
    for match in re.finditer(r'<input[^>]+type="hidden"[^>]+name="([^"]+)"[^>]+value="([^"]*)"', html):
        hidden_fields[match.group(1)] = match.group(2)
    for match in re.finditer(r'<input[^>]+name="([^"]+)"[^>]+type="hidden"[^>]+value="([^"]*)"', html):
        if match.group(1) not in hidden_fields:
            hidden_fields[match.group(1)] = match.group(2)
    log(f"Hidden fields: {list(hidden_fields.keys())}")
    return {"action": action, "hidden_fields": hidden_fields, "html": html}


def generate_pkce():
    """Генерирует code_verifier и code_challenge для PKCE S256."""
    # code_verifier: 43-128 символов из [A-Za-z0-9-._~]
    code_verifier = secrets.token_urlsafe(64)[:64]
    # code_challenge = BASE64URL(SHA256(code_verifier))
    digest = hashlib.sha256(code_verifier.encode('ascii')).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')
    return code_verifier, code_challenge


def _iter_fa_cookies(session, domain_filter=None, name_filter=None):
    """Итератор по cookies с фильтрацией.

    domain_filter: подстрока, которая должна быть в c.domain (например 'org.fa.ru').
                   Если None — все fa.ru cookies.
    name_filter:    set имён cookies, которые нужно оставить.
                   Если None — все имена.
    """
    seen = set()
    for c in session.cookies:
        if "fa.ru" not in c.domain:
            continue
        if domain_filter and domain_filter not in c.domain:
            continue
        if name_filter and c.name not in name_filter:
            continue
        key = (c.name, c.domain)
        if key in seen:
            continue
        seen.add(key)
        yield c


def build_fa_cookie_header(session, domain_filter=None, name_filter=None):
    """Собирает Cookie: header из fa.ru cookies с опциональной фильтрацией.

    По умолчанию (как iOS HTTPCookie.requestHeaderFields) — все fa.ru cookies.
    Это даёт ~6-8KB Cookie, что превышает large_client_header_buffers nginx
    на org.fa.ru (8KB на один header) и приводит к 400.

    Используйте domain_filter='org.fa.ru' или name_filter={'KEYCLOAK_IDENTITY'}
    для минималистичных стратегий.
    """
    pairs = [f"{c.name}={c.value}" for c in _iter_fa_cookies(session, domain_filter, name_filter)]
    return "; ".join(pairs)


def log_cookie_sizes(session):
    """Логирует размер каждого fa.ru cookie — помогает понять 400 от nginx."""
    log(f"Размеры fa.ru cookies:")
    total = 0
    for c in _iter_fa_cookies(session):
        size = len(c.value)
        total += size
        marker = " <<<" if size > 500 else ""
        log(f"  {c.name:42s} {size:6d} байт  [domain={c.domain}]{marker}")
    log(f"  ---")
    log(f"  ВСЕГО: {total} байт")


def log_set_cookie_and_auth(response):
    """Логирует Set-Cookie и WWW-Authenticate из ответа — помогает понять 401."""
    set_cookies = []
    for k, v in response.headers.items():
        if k.lower() == "set-cookie":
            set_cookies.append(v)
    if set_cookies:
        log(f"  Set-Cookie ({len(set_cookies)} шт):")
        for sc in set_cookies[:6]:
            name = sc.split("=", 1)[0]
            rest = sc[len(name)+1:][:80]
            log(f"    {name} = {rest}...")
    www_auth = response.headers.get("WWW-Authenticate")
    if www_auth:
        log(f"  WWW-Authenticate: {www_auth}")


# ============================================================================
# ШАГ 0: Инициация через NextAuth signin
# ============================================================================

def step0_nextauth_signin(session):
    log_separator("ШАГ 0: Инициация через NextAuth signin")
    log(f"GET {SIGNIN_URL}")
    resp, _ = timed_request(session, "GET", SIGNIN_URL)
    log(f"Статус: {resp.status_code}")
    log_cookies(session, "после signin GET")

    csrf_token = extract_csrf_from_cookie(session)
    if not csrf_token:
        log("CSRF токен не найден в cookie!", "ERROR")
        return None
    log(f"CSRF: {csrf_token[:20]}...")

    # POST с CSRF -> получаем URL для Keycloak
    log(f"POST {SIGNIN_URL}")
    body = {"csrfToken": csrf_token, "callbackUrl": LK_BASE, "json": "true"}
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": LK_BASE,
        "Referer": SIGNIN_URL
    }
    resp, _ = timed_request(session, "POST", SIGNIN_URL, data=body, headers=headers)
    log(f"Статус: {resp.status_code}")
    log_cookies(session, "после signin POST")

    ct = resp.headers.get("content-type", "")
    if "json" in ct:
        try:
            data = resp.json()
            if "url" in data:
                auth_url = data["url"]
                log(f"Keycloak auth URL получен")
                return {"type": "auth_url", "url": auth_url}
            if "error" in data:
                log(f"NextAuth ошибка: {data['error']}", "ERROR")
        except Exception as e:
            log(f"Ошибка парсинга JSON: {e}", "ERROR")

    if resp.status_code in (301, 302):
        location = resp.headers.get("Location", "")
        if location.startswith("https://auth.fa.ru"):
            return {"type": "auth_url", "url": location}

    log(f"Неожиданный ответ от NextAuth signin", "ERROR")
    return None


# ============================================================================
# ШАГ 1: Загрузка формы логина Keycloak
# ============================================================================

def step1_load_login_form(session, auth_url):
    log_separator("ШАГ 1: Загрузка формы логина (Keycloak)")
    log(f"GET {auth_url[:120]}...")
    resp, _ = timed_request(session, "GET", auth_url)
    log(f"Статус: {resp.status_code}")

    if resp.status_code in (301, 302):
        location = resp.headers.get("Location", "")
        if location.startswith("/"):
            location = AUTH_BASE + location
        return step1_load_login_form(session, location)

    if resp.status_code == 200:
        log(f"HTML: {len(resp.text)} символов")
        log_cookies(session, "после формы")
        return parse_login_form(resp.text)

    log(f"Неожиданный статус: {resp.status_code}", "ERROR")
    return None


# ============================================================================
# ШАГ 2: Отправка логина и пароля
# ============================================================================

def step2_submit_credentials(session, form_data, username, password):
    log_separator("ШАГ 2: Отправка логина и пароля")
    if not form_data or not form_data.get("action"):
        log("Form action не найден!", "ERROR")
        return None

    action = form_data["action"]
    if action.startswith("/"):
        action = AUTH_BASE + action

    body = form_data.get("hidden_fields", {}).copy()
    body["username"] = username
    body["password"] = password
    body["credentialId"] = ""

    log(f"POST {action[:100]}...")
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": LK_BASE,
        "Referer": LK_BASE
    }
    resp, _ = timed_request(session, "POST", action, data=body, headers=headers)
    log(f"Статус: {resp.status_code}")

    if resp.status_code in (301, 302):
        location = resp.headers.get("Location", "")
        log(f"Пароль верный! Редирект -> {location[:100]}...")
        if "callback/keycloak" in location:
            return {"type": "callback_redirect", "location": location}
        return {"type": "otp_redirect", "location": location}

    if resp.status_code == 200:
        if "kc-otp-form" in resp.text or "kc-otp-login-form" in resp.text:
            log("Найдена OTP-форма")
            return {"type": "otp_form", "form_data": parse_login_form(resp.text)}
        if "kc-form-login" in resp.text:
            log("Неверный логин или пароль", "ERROR")
            return {"type": "error", "message": "Неверный логин или пароль"}

    return None


# ============================================================================
# ШАГ 2b: Отправка OTP
# ============================================================================

def submit_otp_code(session, form_data, otp_code):
    log_separator("ШАГ 2b: Отправка OTP-кода")
    if not form_data or not form_data.get("action"):
        log("OTP form action не найден!", "ERROR")
        return None

    action = form_data["action"]
    if action.startswith("/"):
        action = AUTH_BASE + action

    body = form_data.get("hidden_fields", {}).copy()
    body["otp"] = otp_code

    log(f"POST {action[:100]}...")
    log(f"OTP code: {otp_code}")
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": LK_BASE,
        "Referer": LK_BASE
    }
    resp, _ = timed_request(session, "POST", action, data=body, headers=headers)
    log(f"Статус: {resp.status_code}")

    if resp.status_code in (301, 302):
        location = resp.headers.get("Location", "")
        log(f"OTP верный! -> {location[:100]}...")
        if "callback/keycloak" in location:
            return {"type": "callback_redirect", "location": location}
        return {"type": "redirect", "location": location}

    if resp.status_code == 200:
        if "kc-otp-form" in resp.text or "kc-otp-login-form" in resp.text:
            log("Неверный OTP-код", "ERROR")
            return {"type": "error", "message": "Неверный OTP-код"}

    return None


# ============================================================================
# ШАГ 3: NextAuth Callback
# ============================================================================

def step3_nextauth_callback(session, callback_url):
    log_separator("ШАГ 3: NextAuth Callback (фиксация сессии)")
    log(f"GET {callback_url[:120]}...")
    resp, _ = timed_request(session, "GET", callback_url)
    log(f"Статус: {resp.status_code}")
    log_cookies(session, "после callback")

    if resp.status_code in (301, 302):
        location = resp.headers.get("Location", "")
        log(f"Редирект -> {location}")

        if "error" in location.lower():
            log(f"NextAuth ошибка: {location}", "ERROR")
            return False

        # Следуем за редиректами
        max_redirects = 5
        cur = resp
        while cur.status_code in (301, 302) and max_redirects > 0:
            nxt = cur.headers.get("Location", "")
            if not nxt or "error" in nxt.lower():
                break
            if nxt.startswith("/"):
                nxt = LK_BASE + nxt
            cur, _ = timed_request(session, "GET", nxt)
            max_redirects -= 1

        has_session = any("session-token" in c.name for c in session.cookies)
        if has_session:
            log(f"Сессия NextAuth создана!")
        else:
            log(f"Session cookie не найден", "WARN")
        return has_session

    return resp.status_code == 200


# ============================================================================
# ШАГ 4: Проверка сессии
# ============================================================================

def step4_fetch_session(session):
    log_separator("ШАГ 4: Проверка сессии lk.fa.ru")
    log(f"GET {SESSION_URL}")
    resp, _ = timed_request(session, "GET", SESSION_URL)

    if resp.status_code == 200:
        try:
            data = resp.json()
            user = data.get("user", {})
            log(f"Сессия: {user.get('name', '?')} / {user.get('email', '?')}")
            log(f"  expires: {data.get('expires', '?')}")
            log(f"  accessToken в session: {'ДА' if 'accessToken' in data else 'НЕТ'}")
            log(f"  userId: {data.get('userId', '?')}")
            ext = data.get("extendedUserData", {})
            if ext:
                log(f"  extendedUserData keys: {list(ext.keys())}")
            log(f"\n  Полный JSON сессии:")
            print(json.dumps(data, indent=2, ensure_ascii=False))
            return data
        except Exception as e:
            log(f"Ошибка: {e}", "ERROR")
    log("Сессия не получена", "ERROR")
    return None


# ============================================================================
# ШАГ 5: Получение JWT через SSO С PKCE
# ============================================================================

def step5_get_jwt_via_sso(session):
    log_separator("ШАГ 5: Получение JWT access_token через SSO + PKCE")

    code_verifier, code_challenge = generate_pkce()
    direct_state = "sso_jwt_" + str(int(time.time()))

    auth_url = (
        f"{AUTH_BASE}/realms/elk/protocol/openid-connect/auth"
        f"?client_id={CLIENT_ID}"
        f"&redirect_uri={quote(DIRECT_CALLBACK_URI)}"
        f"&response_type=code"
        f"&scope=openid email profile"
        f"&state={direct_state}"
        f"&code_challenge={code_challenge}"
        f"&code_challenge_method=S256"
    )

    log(f"GET auth (SSO + PKCE)")
    log(f"  code_challenge: {code_challenge[:20]}...")
    log(f"  code_verifier: {code_verifier[:20]}...")

    resp, _ = timed_request(session, "GET", auth_url)
    log(f"Статус: {resp.status_code}")

    if resp.status_code in (301, 302):
        location = resp.headers.get("Location", "")
        log(f"Редирект -> {location[:150]}...")

        code = extract_code(location)
        if code:
            log(f"Code получен через SSO: {code[:20]}...")

            # Обмениваем code на JWT С code_verifier
            token_url = f"{AUTH_BASE}/realms/elk/protocol/openid-connect/token"
            token_body = {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": DIRECT_CALLBACK_URI,
                "client_id": CLIENT_ID,
                "code_verifier": code_verifier
            }

            log(f"\nPOST {token_url}")
            log(f"  grant_type=authorization_code + code_verifier")
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            resp2, _ = timed_request(session, "POST", token_url, data=token_body, headers=headers)
            log(f"Статус: {resp2.status_code}")

            if resp2.status_code == 200:
                try:
                    token_data = resp2.json()
                    access_token = token_data.get("access_token", "")
                    refresh_token = token_data.get("refresh_token", "")
                    expires_in = token_data.get("expires_in", 0)

                    log(f"JWT получен!")
                    log(f"  access_token: {access_token[:50]}..." if access_token else "  access_token: (нет)")
                    log(f"  refresh_token: {refresh_token[:50]}..." if refresh_token else "  refresh_token: (нет)")
                    log(f"  expires_in: {expires_in}с")
                    log(f"  token_type: {token_data.get('token_type', '?')}")

                    # Декодируем JWT payload и подсвечиваем критичные поля
                    if access_token:
                        try:
                            parts = access_token.split(".")
                            if len(parts) >= 2:
                                payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
                                payload_json = base64.urlsafe_b64decode(payload_b64)
                                payload = json.loads(payload_json)
                                log(f"\n  JWT payload:")
                                print(json.dumps(payload, indent=2, ensure_ascii=False)[:1500])
                                # Подсветка критичных для org.fa.ru полей
                                log(f"\n  КЛЮЧЕВЫЕ ПОЛЯ JWT для org.fa.ru:")
                                log(f"    iss:             {payload.get('iss')}")
                                log(f"    aud:             {payload.get('aud')}")
                                log(f"    azp:             {payload.get('azp')}")
                                log(f"    allowed-origins: {payload.get('allowed-origins')}")
                                log(f"    scope:           {payload.get('scope')}")
                                log(f"    exp:             {payload.get('exp')} ({datetime.utcfromtimestamp(payload.get('exp', 0)).isoformat() if payload.get('exp') else '?'})")
                                if payload.get('aud') == 'account':
                                    log(f"    WARNING: aud='account' — дефолтный Keycloak audience,", "WARN")
                                    log(f"             org.fa.ru может отвергать по azp/aud/allowed-origins", "WARN")
                        except Exception as e:
                            log(f"  Не удалось декодировать JWT: {e}", "WARN")

                    return token_data
                except Exception as e:
                    log(f"Ошибка парсинга token: {e}", "ERROR")
            else:
                log(f"Ошибка обмена code: {resp2.status_code}", "ERROR")
                log(f"Тело: {resp2.text[:300]}")
            return None

        # Нет code в URL — возможно SSO не сработало
        log(f"Code не найден в URL", "WARN")
        if location.startswith(AUTH_BASE):
            resp3, _ = timed_request(session, "GET", location)
            if resp3.status_code == 200 and "kc-form-login" in resp3.text:
                log("SSO не сработал — требуется повторная авторизация", "ERROR")
        return None

    if resp.status_code == 200:
        log("SSO не сработал — 200 вместо редиректа", "WARN")
        if "kc-form-login" in resp.text:
            log("Keycloak показывает форму логина", "ERROR")
        return None

    log(f"Неожиданный статус: {resp.status_code}", "ERROR")
    return None


# ============================================================================
# ШАГ 5b: SSO-handshake с org.fa.ru (ПОЛНАЯ цепочка + парсинг JS-редиректа)
# ============================================================================

# Эндпоинт Bitrix SSO: возвращает JSON с auth_url к Keycloak
BITRIX_SSO_LINK_URL = "https://org.fa.ru/bitrix/vuz/sso/link"
BITRIX_SSO_CALLBACK_URL = "https://org.fa.ru/bitrix/vuz/sso/callback"


def step5b_init_bitrix_session(session, access_token=""):
    """Инициализирует Bitrix-сессию на org.fa.ru через ПОЛНЫЙ SSO chain.

    ОТКРЫТИЕ v9 (из ручного инспектирования sso-init.php):
    /local/auth/sso-init.php возвращает HTML с JS, который делает:
        fetch('/bitrix/vuz/sso/link?backurl=%2F', {credentials: 'include'})
        .then(r => r.json())
        .then(data => { window.location.href = data.auth_url; })

    /bitrix/vuz/sso/link возвращает JSON:
        {"auth_url": "https://auth.fa.ru/realms/elk/protocol/openid-connect/auth
                     ?client_id=orgfaru-client
                     &redirect_uri=https://org.fa.ru/bitrix/vuz/sso/callback
                     &response_type=code&scope=openid profile email&state=XXX"}

    Полный flow (воспроизводим поведение браузера):
      1) GET / — получаем PHPSESSID, session-cookie (Bitrix guest session)
      2) GET /bitrix/vuz/sso/link?backurl=%2F — получаем auth_url к Keycloak
         с client_id=orgfaru-client. Также ставится vuzportalfinun_session.
      3) GET auth_url — Keycloak видит KEYCLOAK_IDENTITY cookie (SSO) и
         сразу 302 на https://org.fa.ru/bitrix/vuz/sso/callback?code=XXX&state=YYY
         (БЕЗ повторного OTP).
      4) GET /bitrix/vuz/sso/callback?code=XXX&state=YYY — Bitrix обменивает
         code на JWT (через свой клиент orgfaru-client), создаёт пользователя
         в своей БД и выставляет cookies:
           BX_ORG_FA_RU_UIDL=240767      (user login)
           BX_ORG_FA_RU_UIDH=...         (user hash)
           BX_ORG_FA_RU_GUEST_ID=...
           BX_ORG_FA_RU_PROFILE_ID=...
           BX_ORG_FA_RU_TZ=Europe/Moscow
           vuzportalfinun_session=...    (уже был, обновляется)
      5) GET /app/profile/home — догружаем метаданные (LAST_VISIT, SOUND_LOGIN_PLAYED).

    После этого все запросы к /bitrix/vuz/api/* работают ТОЛЬКО на cookies.
    JWT вообще не нужен (Bitrix использует собственную сессию).
    """
    log_separator("ШАГ 5b: SSO-handshake с org.fa.ru (ПОЛНАЯ цепочка через sso/link)")

    # --- 5b-1: GET / — получаем PHPSESSID и session-cookie ---
    log(f"\n--- 5b-1: GET / (получение PHPSESSID) ---")
    log(f"GET https://org.fa.ru/")
    resp, _ = timed_request(session, "GET", "https://org.fa.ru/", allow_redirects=False)
    log(f"Статус: {resp.status_code}")
    loc = resp.headers.get("Location", "")
    if loc:
        log(f"Location: {loc[:120]}")
    log_set_cookie_and_auth(resp)

    # --- 5b-2: GET /bitrix/vuz/sso/link?backurl=%2F — JSON с auth_url ---
    log(f"\n--- 5b-2: GET /bitrix/vuz/sso/link?backurl=%2F (получение auth_url) ---")
    sso_link_url = f"{BITRIX_SSO_LINK_URL}?backurl=%2F"
    sso_link_headers = {
        "Accept": "*/*",
        "Referer": "https://org.fa.ru/local/auth/sso-init.php?backurl=%2F",
    }
    log(f"GET {sso_link_url}")
    resp, _ = timed_request(session, "GET", sso_link_url, headers=sso_link_headers)
    log(f"Статус: {resp.status_code}")
    log_set_cookie_and_auth(resp)

    auth_url = None
    if resp.status_code == 200:
        try:
            data = resp.json()
            auth_url = data.get("auth_url", "")
            log(f"auth_url получен: {auth_url[:200]}...")
            # Парсим параметры
            parsed = urlparse(auth_url)
            params = parse_qs(parsed.query)
            log(f"  client_id:    {params.get('client_id', ['?'])[0]}")
            log(f"  redirect_uri: {params.get('redirect_uri', ['?'])[0]}")
            log(f"  response_type: {params.get('response_type', ['?'])[0]}")
            log(f"  scope:        {params.get('scope', ['?'])[0]}")
            log(f"  state:        {params.get('state', ['?'])[0]}")
        except Exception as e:
            log(f"Ошибка парсинга JSON: {e}", "ERROR")
            log(f"Тело: {resp.text[:300]}")

    if not auth_url:
        log(f"auth_url не получен — SSO-handshake не возможен", "FATAL")
        return

    # --- 5b-3: GET auth_url на Keycloak (SSO — KEYCLOAK_IDENTITY уже есть) ---
    log(f"\n--- 5b-3: GET auth_url на Keycloak (SSO) ---")
    log(f"GET {auth_url[:120]}...")
    # Keycloak должен увидеть KEYCLOAK_IDENTITY и сразу 302 на callback с code
    resp, _ = timed_request(session, "GET", auth_url, allow_redirects=False)
    log(f"Статус: {resp.status_code}")
    loc = resp.headers.get("Location", "")
    log(f"Location: {loc[:200]}")
    log_set_cookie_and_auth(resp)

    code = None
    state_from_kc = None
    if resp.status_code in (301, 302) and loc:
        # Ожидаем: https://org.fa.ru/bitrix/vuz/sso/callback?code=XXX&state=YYY
        parsed = urlparse(loc)
        params = parse_qs(parsed.query)
        code = params.get("code", [None])[0]
        state_from_kc = params.get("state", [None])[0]
        if code:
            log(f">>> Code получен: {code[:25]}...", "INFO")
            log(f">>> State: {state_from_kc}")
        else:
            log(f"Code не найден в Location", "ERROR")
            # Если Location ведёт на auth.fa.ru/login-actions/authenticate —
            # значит Keycloak требует повторный логин (SSO не сработал)
            if "auth.fa.ru" in loc:
                log(f"Keycloak требует повторный логин — SSO не сработал", "ERROR")
    else:
        log(f"Ожидался 302 от Keycloak, получен {resp.status_code}", "ERROR")
        if resp.status_code == 200 and "kc-form-login" in resp.text:
            log(f"Keycloak показывает форму логина — SSO не сработал", "ERROR")

    if not code:
        log(f"Code не получен — SSO-handshake прерван", "FATAL")
        return

    # --- 5b-4: GET /bitrix/vuz/sso/callback?code=XXX&state=YYY ---
    # Bitrix обменивает code на JWT (через orgfaru-client), создаёт сессию
    callback_url = f"{BITRIX_SSO_CALLBACK_URL}?code={code}&state={state_from_kc}"
    log(f"\n--- 5b-4: GET /bitrix/vuz/sso/callback?code=... (создание Bitrix-сессии) ---")
    log(f"GET {callback_url[:120]}...")
    callback_headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Referer": "https://auth.fa.ru/",
    }
    # allow_redirects=True: Bitrix может редиректить обратно на /
    resp, _ = timed_request(session, "GET", callback_url,
                            headers=callback_headers, allow_redirects=True)
    log(f"Финальный статус: {resp.status_code}")
    log(f"Финальный URL: {resp.url[:120]}")
    log(f"История редиректов ({len(resp.history)} шт):")
    for i, h in enumerate(resp.history):
        log(f"  [{i+1}] {h.status_code} {h.url[:100]}")
        l = h.headers.get("Location", "")
        if l:
            log(f"        -> {l[:120]}")
    log_set_cookie_and_auth(resp)

    # --- 5b-5: Проверяем, появились ли BX_ORG_FA_RU_* cookies ---
    bx_cookies = [c for c in session.cookies if "BX_ORG_FA_RU" in c.name]
    log(f"\n--- 5b-5: BX_ORG_FA_RU cookies после SSO ---")
    if bx_cookies:
        log(f"  НАЙДЕНО {len(bx_cookies)} шт:", "INFO")
        for c in bx_cookies:
            val = c.value[:40] + "..." if len(c.value) > 40 else c.value
            log(f"    {c.name} = {val}  [domain={c.domain}]")
    else:
        log(f"  НЕ найдено — Bitrix не создал сессию", "ERROR")

    # --- 5b-6: GET /app/profile/home — догружаем метаданные ---
    log(f"\n--- 5b-6: GET /app/profile/home ---")
    resp, _ = timed_request(session, "GET", "https://org.fa.ru/app/profile/home", allow_redirects=True)
    log(f"Статус: {resp.status_code}")
    log_set_cookie_and_auth(resp)

    # --- 5b-7: Логируем все fa.ru cookies с размерами ---
    log(f"\nКуки .fa.ru после handshake ({sum(1 for c in session.cookies if 'fa.ru' in c.domain)} шт):")
    for c in session.cookies:
        if "fa.ru" not in c.domain:
            continue
        val = c.value[:40] + "..." if len(c.value) > 40 else c.value
        log(f"  {c.name} = {val}  [domain={c.domain}, path={c.path}, size={len(c.value)}b]")

    log("")
    log_cookie_sizes(session)


# ============================================================================
# ШАГ 5c: Исследование OAuth flow org.fa.ru (поиск правильного client_id)
# ============================================================================

def step5c_explore_org_fa_ru_auth(session, current_access_token=""):
    """Исследует, как org.fa.ru авторизует пользователей.

    Гипотеза: JWT, полученный через client_id=elk-front, имеет
    aud='account', allowed-origins=['https://lk.fa.ru'] — он невалиден
    для org.fa.ru. Bitrix, скорее всего, использует ДРУГОЙ Keycloak
    client (с собственным aud/azp/allowed-origins).

    Чтобы найти правильный client_id:
      1) GET /bitrix/vuz/api/profile/current в чистой сессии — Bitrix
         может вернуть 401 с Location на Keycloak auth URL.
      2) GET /login, /auth/login — стандартные URL для логина.
      3) GET / (root) — HTML может содержать JS с OAuth config.
      4) GET /app/profile/home — HTML может содержать meta или JS
         с client_id и redirect_uri.

    Также пробуем Keycloak token-exchange: обменять наш JWT на токен
    с другим audience (если Keycloak это поддерживает).
    """
    log_separator("ШАГ 5c: Исследование OAuth flow org.fa.ru")

    # Чистая сессия (без cookies) для поиска redirect'а на Keycloak
    fresh = requests.Session()
    fresh.headers.update({
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "ru"
    })

    found_keycloak_urls = []

    # --- 5c-1: Probe URLs ---
    probe_urls = [
        "https://org.fa.ru/bitrix/vuz/api/profile/current",
        "https://org.fa.ru/login",
        "https://org.fa.ru/auth/login",
        "https://org.fa.ru/oauth/login",
        "https://org.fa.ru/app/login",
        "https://org.fa.ru/",
        "https://org.fa.ru/app/profile/home",
    ]

    js_bundles_to_check = []  # соберём URL'ы JS для парсинга

    for url in probe_urls:
        log(f"\n--- GET {url} (clean session) ---")
        try:
            resp, _ = timed_request(fresh, "GET", url, allow_redirects=False)
        except Exception as e:
            log(f"  Ошибка: {e}", "ERROR")
            continue
        log(f"  Статус: {resp.status_code}")
        loc = resp.headers.get("Location", "")
        if loc:
            log(f"  Location: {loc[:200]}")
            if "auth.fa.ru" in loc:
                found_keycloak_urls.append(loc)
                # Извлекаем client_id из URL
                parsed = urlparse(loc)
                params = parse_qs(parsed.query)
                cid = params.get("client_id", ["?"])[0]
                ruri = params.get("redirect_uri", ["?"])[0]
                log(f"  >>> НАЙДЕН Keycloak auth URL!", "INFO")
                log(f"      client_id:    {cid}")
                log(f"      redirect_uri: {ruri}")
        # Если 200 — ищем в HTML упоминания auth.fa.ru или client_id
        if resp.status_code == 200 and "text/html" in resp.headers.get("Content-Type", "").lower():
            html = resp.text
            log(f"  HTML размер: {len(html)} символов")
            # Ищем client_id в HTML/JS
            for pattern in [
                r'client_id["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                r'clientId["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                r'auth\.fa\.ru[^"\s]*client_id=([^&"\s]+)',
            ]:
                m = re.search(pattern, html)
                if m:
                    log(f"  >>> НАЙДЕН client_id в HTML: {m.group(1)}", "INFO")
            # Ищем URL авторизации
            for kw in ["auth.fa.ru", "openid-connect", "oauth", "keycloak"]:
                if kw in html:
                    idx = html.index(kw)
                    snippet = html[max(0, idx-50):idx+200]
                    log(f"  >>> Найдено '{kw}' в HTML: ...{snippet}...")
                    break
            # Ищем ссылки на JS bundle
            js_matches = re.findall(r'<script[^>]+src="([^"]+\.js[^"]*)"', html)
            if js_matches:
                log(f"  JS bundles: {js_matches[:5]}")
                # Запоминаем для последующего парсинга (только с того же домена)
                for js_url in js_matches[:5]:
                    if not js_url.startswith("http"):
                        js_url = "https://org.fa.ru/" + js_url.lstrip("/")
                    js_bundles_to_check.append(js_url)

    # --- 5c-2: Следуем по redirect chain / -> /local/auth/sso-init.php -> auth.fa.ru ---
    log(f"\n--- 5c-2: Following redirect chain from / ---")
    chain_session = requests.Session()
    chain_session.headers.update({
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "ru"
    })
    chain_url = "https://org.fa.ru/"
    chain_steps = 0
    while chain_steps < 10:
        log(f"\n  Шаг {chain_steps+1}: GET {chain_url[:120]}")
        try:
            resp, _ = timed_request(chain_session, "GET", chain_url, allow_redirects=False)
        except Exception as e:
            log(f"    Ошибка: {e}", "ERROR")
            break
        log(f"    Статус: {resp.status_code}")
        # Логируем все Set-Cookie
        log_set_cookie_and_auth(resp)
        loc = resp.headers.get("Location", "")
        if not loc:
            log(f"    Location пустой — цепочка завершена")
            # Если это HTML — ищем auth.fa.ru / sso / login
            if "text/html" in resp.headers.get("Content-Type", "").lower():
                html = resp.text
                log(f"    HTML размер: {len(html)} символов")
                for kw in ["auth.fa.ru", "openid-connect", "client_id", "sso", "keycloak"]:
                    if kw in html.lower():
                        idx = html.lower().index(kw)
                        snippet = html[max(0, idx-30):idx+200]
                        log(f"    >>> Найдено '{kw}' в HTML:")
                        log(f"    ...{snippet}...")
            break
        log(f"    Location: {loc[:200]}")
        # Разрешаем относительные URL
        if loc.startswith("/"):
            parsed = urlparse(chain_url)
            loc = f"{parsed.scheme}://{parsed.netloc}{loc}"
        # Если дошли до auth.fa.ru — это победа
        if "auth.fa.ru" in loc:
            log(f"    >>> ДОШЛИ ДО Keycloak auth URL!", "INFO")
            found_keycloak_urls.append(loc)
            parsed = urlparse(loc)
            params = parse_qs(parsed.query)
            cid = params.get("client_id", ["?"])[0]
            ruri = params.get("redirect_uri", ["?"])[0]
            log(f"    >>> client_id:    {cid}")
            log(f"    >>> redirect_uri: {ruri}")
            break
        chain_url = loc
        chain_steps += 1

    # --- 5c-3: Парсим JS бандлы на предмет OAuth config ---
    if js_bundles_to_check and not found_keycloak_urls:
        log(f"\n--- 5c-3: Парсинг JS бандлов ---")
        for js_url in js_bundles_to_check[:3]:
            log(f"\n  GET {js_url}")
            try:
                resp, _ = timed_request(fresh, "GET", js_url, allow_redirects=True)
            except Exception as e:
                log(f"    Ошибка: {e}", "ERROR")
                continue
            log(f"    Статус: {resp.status_code}, размер: {len(resp.text)} символов")
            if resp.status_code != 200:
                continue
            js_text = resp.text
            # Ищем client_id в JS
            for pattern in [
                r'client_id["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                r'clientId["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                r'realm["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                r'auth\.fa\.ru[^"\s]*client_id=([^&"\s]+)',
                r'redirect_uri["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                r'url:\s*["\']([^"\']*openid-connect[^"\']*)["\']',
            ]:
                matches = re.findall(pattern, js_text)
                if matches:
                    log(f"    >>> НАЙДЕНЫ совпадения по pattern '{pattern[:40]}': {set(matches)}")
            # Ищем контекст вокруг auth.fa.ru
            for kw in ["auth.fa.ru", "openid-connect", "realms/", "keycloak"]:
                idx = js_text.find(kw)
                if idx >= 0:
                    snippet = js_text[max(0, idx-80):idx+200]
                    log(f"    >>> '{kw}' в JS: ...{snippet}...")

    # --- 5c-4: Keycloak token-exchange (если нашли URL) ---
    if current_access_token and found_keycloak_urls:
        log(f"\n--- Keycloak token-exchange (пробуем) ---")
        # Извлекаем client_id из найденного URL
        parsed = urlparse(found_keycloak_urls[0])
        params = parse_qs(parsed.query)
        target_client_id = params.get("client_id", [""])[0]
        target_redirect = params.get("redirect_uri", [""])[0]
        if target_client_id and target_client_id != CLIENT_ID:
            log(f"  Целевой client_id: {target_client_id}")
            log(f"  Целевой redirect_uri: {target_redirect}")
            token_url = f"{AUTH_BASE}/realms/elk/protocol/openid-connect/token"
            body = {
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": current_access_token,
                "subject_issuer": f"{AUTH_BASE}/realms/elk",
                "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "client_id": CLIENT_ID,
                "audience": target_client_id,
            }
            log(f"  POST {token_url}")
            log(f"  grant_type=token-exchange, audience={target_client_id}")
            resp, _ = timed_request(session, "POST", token_url,
                                    data=body,
                                    headers={"Content-Type": "application/x-www-form-urlencoded"})
            log(f"  Статус: {resp.status_code}")
            if resp.status_code == 200:
                try:
                    new_token = resp.json()
                    log(f"  >>> Token exchange УСПЕШЕН!", "INFO")
                    log(f"      access_token: {new_token.get('access_token', '')[:60]}...")
                    return new_token
                except Exception as e:
                    log(f"  Ошибка парсинга: {e}", "ERROR")
            else:
                log(f"  Тело: {resp.text[:400]}")
                log(f"  (token-exchange может быть отключён в Keycloak)", "WARN")
        else:
            log(f"  Целевой client_id совпадает с текущим или не найден — exchange не нужен")
    elif current_access_token:
        log(f"\n--- Keycloak auth URL не найден — пропускаем token-exchange ---")

    # Сохраняем найденные URL для использования в шаге 5d
    return {"keycloak_urls": found_keycloak_urls}


# ============================================================================
# ШАГ 5d: SSO с правильным client_id (если найден в 5c)
# ============================================================================

def step5d_sso_with_target_client(session, target_client_id, target_redirect_uri):
    """Делает SSO-запрос к Keycloak с правильным client_id для org.fa.ru.

    Если в шаге 5c мы нашли, что org.fa.ru использует client_id=foo
    с redirect_uri=https://org.fa.ru/callback, то делаем новый SSO:
      1) GET https://auth.fa.ru/realms/elk/protocol/openid-connect/auth
         ?client_id=foo&redirect_uri=https://org.fa.ru/callback&...
         (с нашим PKCE)
      2) Keycloak видит KEYCLOAK_IDENTITY, сразу редиректит с code
         (без повторного OTP, потому что SSO)
      3) Обмениваем code на JWT через token endpoint
      4) Этот JWT будет иметь правильный aud/azp/allowed-origins для org.fa.ru

    Возвращает token_data (dict) или None.
    """
    log_separator("ШАГ 5d: SSO с правильным client_id для org.fa.ru")

    if not target_client_id or target_client_id == CLIENT_ID:
        log(f"  Целевой client_id не найден или совпадает с elk-front — шаг пропущен", "WARN")
        return None

    log(f"  Целевой client_id:    {target_client_id}")
    log(f"  Целевой redirect_uri: {target_redirect_uri}")

    code_verifier, code_challenge = generate_pkce()
    direct_state = "sso_org_" + str(int(time.time()))

    auth_url = (
        f"{AUTH_BASE}/realms/elk/protocol/openid-connect/auth"
        f"?client_id={target_client_id}"
        f"&redirect_uri={quote(target_redirect_uri)}"
        f"&response_type=code"
        f"&scope=openid email profile"
        f"&state={direct_state}"
        f"&code_challenge={code_challenge}"
        f"&code_challenge_method=S256"
    )

    log(f"\nGET auth (SSO + PKCE + target client)")
    log(f"  code_challenge: {code_challenge[:20]}...")
    log(f"  code_verifier:  {code_verifier[:20]}...")

    resp, _ = timed_request(session, "GET", auth_url)
    log(f"Статус: {resp.status_code}")

    if resp.status_code in (301, 302):
        location = resp.headers.get("Location", "")
        log(f"Редирект -> {location[:200]}...")

        code = extract_code(location)
        if code:
            log(f"Code получен: {code[:20]}...")
            token_url = f"{AUTH_BASE}/realms/elk/protocol/openid-connect/token"
            token_body = {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": target_redirect_uri,
                "client_id": target_client_id,
                "code_verifier": code_verifier
            }
            log(f"\nPOST {token_url}")
            log(f"  grant_type=authorization_code + code_verifier")
            resp2, _ = timed_request(session, "POST", token_url,
                                     data=token_body,
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
            log(f"Статус: {resp2.status_code}")

            if resp2.status_code == 200:
                try:
                    token_data = resp2.json()
                    at = token_data.get("access_token", "")
                    log(f"JWT получен!")
                    log(f"  access_token: {at[:60]}...")
                    # Декодируем и сравниваем с предыдущим
                    if at:
                        try:
                            parts = at.split(".")
                            payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
                            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
                            log(f"\n  КЛЮЧЕВЫЕ ПОЛЯ нового JWT:")
                            log(f"    iss:             {payload.get('iss')}")
                            log(f"    aud:             {payload.get('aud')}")
                            log(f"    azp:             {payload.get('azp')}")
                            log(f"    allowed-origins: {payload.get('allowed-origins')}")
                            log(f"    scope:           {payload.get('scope')}")
                        except Exception as e:
                            log(f"  Не удалось декодировать JWT: {e}", "WARN")
                    return token_data
                except Exception as e:
                    log(f"Ошибка парсинга: {e}", "ERROR")
            else:
                log(f"Тело: {resp2.text[:400]}", "ERROR")
        else:
            log(f"Code не найден в URL редиректа", "WARN")
    elif resp.status_code == 200:
        log(f"SSO не сработало — 200 вместо редиректа", "WARN")
        if "kc-form-login" in resp.text:
            log(f"Keycloak требует повторный логин для client_id={target_client_id}", "ERROR")
            log(f"(Возможно, этот client требует повторной аутентификации)", "WARN")

    return None


# ============================================================================
# ШАГ 6: Загрузка данных профиля
# ============================================================================

def _bitrix_base_headers(access_token, session, with_cookies=True,
                         cookie_domain_filter=None, cookie_name_filter=None):
    """Базовые заголовки для org.fa.ru API.

    with_cookies:           добавлять ли Cookie: вообще.
    cookie_domain_filter:   только cookies с этим подстрокой в domain
                            (например 'org.fa.ru' только Bitrix-сессия).
    cookie_name_filter:     set имён cookies (например {'KEYCLOAK_IDENTITY'}
                            для минимального Keycloak adapter сценария).
    """
    h = {
        "App-Version": "8.135.3",
        "App-Key": "browser-bitrix",
        "App-Locale": "ru",
        "App-TimezoneOffset": "-180",
        "Accept": "application/json",
    }
    if access_token:
        h["Authorization"] = f"Bearer {access_token}"
    if with_cookies:
        cookie_hdr = build_fa_cookie_header(session, cookie_domain_filter, cookie_name_filter)
        if cookie_hdr:
            h["Cookie"] = cookie_hdr
    return h


def _log_header_sizes(h):
    """Логирует размеры ключевых заголовков — помогает понять 400 от nginx."""
    cookie_sz = len(h.get("Cookie", ""))
    auth_sz = len(h.get("Authorization", ""))
    log(f"     Cookie: {cookie_sz} байт, Authorization: {auth_sz} байт, сумма: {cookie_sz+auth_sz} байт")
    if cookie_sz + auth_sz > 7000:
        log(f"     WARNING: сумма > 7KB — риск 400 'Request Header Or Cookie Too Large'", "WARN")


def _try_bitrix_with_strategies(session, url, access_token, label, extra_headers=None):
    """Перебирает стратегии auth, если базовая вернёт 401/400.

    ОТКРЫТИЕ v8 (из реального браузерного curl):
    org.fa.ru использует Bitrix session cookies, а НЕ JWT!
    Рабочий curl из браузера НЕ содержит Authorization: Bearer ...
    и НЕ содержит KEYCLOAK_IDENTITY. Только:
      BX_ORG_FA_RU_UIDL, BX_ORG_FA_RU_UIDH, BX_ORG_FA_RU_GUEST_ID,
      BX_ORG_FA_RU_PROFILE_ID, vuzportalfinun_session, PHPSESSID,
      session-cookie, BX_ORG_FA_RU_TZ, vuzportal_is_bitrix_disabled, empty.

    Поэтому ОСНОВНАЯ стратегия — cookies-only без JWT:
      A) ТОЛЬКО cookies (без Authorization) — как браузер
      B) cookies + JWT — проверить, нужен ли вообще JWT
      C) cookies без BX_* (минимум)
      D) JWT-only (без cookies)
      E) JWT + KEYCLOAK_IDENTITY
      F) JWT + ALL fa.ru cookies (последний шанс)

    Возвращает (status_code, resp, used_strategy).
    """
    # Стратегия A: только cookies БЕЗ JWT (как браузер)
    # Фильтр по домену org.fa.ru — это и есть BX_ORG_FA_RU_* cookies
    strategies = [
        ("A: cookies-only (browser-like, NO JWT)",
         _bitrix_base_headers(None, session, with_cookies=True,
                              cookie_domain_filter="org.fa.ru")),
        ("B: cookies + JWT (проверка нужен ли JWT)",
         _bitrix_base_headers(access_token, session, with_cookies=True,
                              cookie_domain_filter="org.fa.ru")),
        ("C: ALL fa.ru cookies (no JWT)",
         _bitrix_base_headers(None, session, with_cookies=True)),
        ("D: JWT-only (no cookies)",
         _bitrix_base_headers(access_token, session, with_cookies=False)),
        ("E: JWT+KEYCLOAK_IDENTITY",
         _bitrix_base_headers(access_token, session, with_cookies=True,
                              cookie_name_filter={"KEYCLOAK_IDENTITY"})),
        ("F: JWT+ALL fa.ru cookies",
         _bitrix_base_headers(access_token, session, with_cookies=True)),
    ]

    last_resp = None
    last_strategy = None
    for name, h in strategies:
        if extra_headers:
            h = {**h, **extra_headers}
        log(f"\n  >> Стратегия {name}")
        _log_header_sizes(h)
        resp, _ = timed_request(session, "GET", url, headers=h)
        log(f"     статус: {resp.status_code}")
        if resp.status_code == 200:
            return 200, resp, name
        if resp.status_code in (301, 302):
            loc = resp.headers.get("Location", "")
            log(f"     Location: {loc[:120]}")
        else:
            log(f"     тело: {resp.text[:150]}")
            log_set_cookie_and_auth(resp)
        last_resp = resp
        last_strategy = name

    return (last_resp.status_code if last_resp else 0), last_resp, last_strategy


def step6_fetch_profile(session, session_data, token_data):
    log_separator("ШАГ 6: Загрузка данных профиля")
    results = {}

    access_token = token_data.get("access_token", "") if token_data else ""
    has_token = bool(access_token)
    log(f"Access token: {'ДА' if has_token else 'НЕТ'}")
    log(f"Cookie header собран: {'ДА' if build_fa_cookie_header(session) else 'НЕТ'}")

    # ВАЖНО: вычисляем profile_id ДО блока 6d, чтобы не словить
    # UnboundLocalError (раньше переменная использовалась до определения).
    profile_id = ""
    if session_data:
        profile_id = session_data.get("userId", "")
        if not profile_id:
            ext = session_data.get("extendedUserData", {})
            profile_id = ext.get("id", ext.get("userUid", ""))
    log(f"profile_id (из session): {profile_id or '(нет)'}")

    # --- 6a: Bitrix профиль (org.fa.ru) ---
    log(f"\n--- 6a: Bitrix профиль (org.fa.ru) ---")
    status, resp, used = _try_bitrix_with_strategies(
        session, BITRIX_PROFILE_URL, access_token, "profile")
    log(f"Использована стратегия: {used or '(нет)'}")

    if status == 200 and resp is not None:
        try:
            profile = resp.json()
            log(f"Профиль получен!")
            u = profile.get("user", {})
            log(f"  ФИО: {u.get('fullname', '?')}")
            log(f"  Курс: {profile.get('edu_course', '?')}")
            log(f"  Форма: {profile.get('edu_form', '?')}")
            log(f"\n  Полные данные:")
            print(json.dumps(profile, indent=2, ensure_ascii=False)[:1500])
            results["profile"] = profile
            # Если в профиле есть id — обновляем profile_id для 6d
            pid = profile.get("id") or profile.get("user", {}).get("id")
            if pid:
                profile_id = str(pid)
                log(f"  profile_id обновлён из Bitrix: {profile_id}")
        except Exception as e:
            log(f"Ошибка: {e}", "ERROR")
            log(f"Тело: {resp.text[:300]}")
    else:
        log(f"Профиль: {status} (все стратегии провалены)", "ERROR")

    # --- 6b: Приказы (org.fa.ru) ---
    log(f"\n--- 6b: Приказы (org.fa.ru) ---")
    status, resp, used = _try_bitrix_with_strategies(
        session, BITRIX_ORDERS_URL, access_token, "orders")
    log(f"Использована стратегия: {used or '(нет)'}")

    if status == 200 and resp is not None:
        try:
            orders = resp.json()
            count = len(orders) if isinstance(orders, list) else "?"
            log(f"Приказы: {count} шт")
            if isinstance(orders, list):
                for i, o in enumerate(orders[:5]):
                    log(f"  [{i+1}] {o.get('title', '?')} от {o.get('date', '?')}")
            results["orders"] = orders
        except Exception as e:
            log(f"Ошибка парсинга: {e}", "ERROR")
            log(f"Тело: {resp.text[:300]}")
    else:
        log(f"Приказы: {status} (все стратегии провалены)", "ERROR")

    # --- 6c: Зачётная книжка (org.fa.ru/bitrix/vuz/api/marks2) ---
    log(f"\n--- 6c: Зачётная книжка (org.fa.ru/bitrix/vuz/api/marks2) ---")
    status, resp, used = _try_bitrix_with_strategies(
        session, BITRIX_MARKS_URL, access_token, "marks",
        extra_headers={"X-Requested-With": "XMLHttpRequest"})
    log(f"Использована стратегия: {used or '(нет)'}")

    if status == 200 and resp is not None:
        try:
            marks_data = resp.json()
            if isinstance(marks_data, list):
                log(f"Зачётная книжка: {len(marks_data)} учебных годов")
                for y in marks_data[:3]:
                    year = y.get("year", "?")
                    semesters = y.get("semesters", [])
                    total_rows = sum(len(s.get("data", [])) for s in semesters)
                    log(f"  {year}/{year+1}: {len(semesters)} семестров, {total_rows} записей")
                results["marks"] = marks_data
            else:
                log(f"Неожиданный формат: {type(marks_data)}")
                log(f"Тело: {resp.text[:500]}")
        except Exception as e:
            log(f"Ошибка парсинга: {e}", "ERROR")
            log(f"Тело: {resp.text[:500]}")
    else:
        log(f"Зачётная книжка: {status} (все стратегии провалены)", "ERROR")

    # --- 6d: Студенческий билет (org.fa.ru, Bearer token) ---
    if profile_id:
        log(f"\n--- 6d: Студенческий билет (org.fa.ru) ---")
        card_api_url = f"{BITRIX_STUDENT_CARD_URL}{profile_id}"
        status, resp, used = _try_bitrix_with_strategies(
            session, card_api_url, access_token, "studentCard",
            extra_headers={"Referer": "https://org.fa.ru/app/profile/home"})
        log(f"Использована стратегия: {used or '(нет)'}")

        if status == 200 and resp is not None:
            try:
                card_resp = resp.json()
                pdf_path = card_resp.get("path", "")
                log(f"Студенческий билет: ответ получен")
                log(f"  error: {card_resp.get('error', 'нет')}")
                log(f"  status: {card_resp.get('status', '?')}")
                log(f"  path: {pdf_path}")
                if pdf_path:
                    pdf_url = f"https://org.fa.ru{pdf_path}"
                    log(f"\n  Загрузка PDF: {pdf_url}")
                    pdf_headers = _bitrix_base_headers(access_token, session, with_cookies=True)
                    pdf_headers["Accept"] = "*/*"
                    pdf_headers["Referer"] = "https://org.fa.ru/app/profile/home"
                    pdf_resp, _ = timed_request(session, "GET", pdf_url, headers=pdf_headers)
                    log(f"  PDF статус: {pdf_resp.status_code}")
                    log(f"  PDF размер: {len(pdf_resp.content)} байт")
                    if pdf_resp.status_code == 200 and len(pdf_resp.content) > 1000:
                        log(f"  PDF загружен успешно!")
                    else:
                        log(f"  PDF не загружен", "WARN")
                results["student_card"] = card_resp
            except Exception as e:
                log(f"Ошибка: {e}", "ERROR")
                log(f"Тело: {resp.text[:300]}")
        else:
            log(f"Студенческий билет: {status} (все стратегии провалены)", "ERROR")
    else:
        log(f"\n--- 6d: Студенческий билет --- пропуск (нет profile_id)")

    # --- 6e: Student ID (через lk.fa.ru cookies) ---
    if profile_id:
        log(f"\n--- 6e: Student ID (lk.fa.ru) ---")
        s_headers = {"Referer": f"{LK_BASE}/elk/profile/STUDENT/{profile_id}"}
        resp, _ = timed_request(session, "GET", STUDENT_ID_URL, headers=s_headers)
        log(f"Статус: {resp.status_code}")
        if resp.status_code == 200:
            try:
                sid = resp.json()
                log(f"Student ID получен!")
                print(json.dumps(sid, indent=2, ensure_ascii=False))
                results["student_id"] = sid
            except Exception:
                log(f"Тело: {resp.text[:300]}")
        else:
            log(f"Student ID: {resp.status_code}", "ERROR")
    else:
        log(f"\n--- 6e: Student ID --- пропуск (нет profile_id)")

    return results


# ============================================================================
# MAIN
# ============================================================================

def main():
    if len(sys.argv) < 3:
        print("Использование: python3 lk_auth_diagnostic.py <логин> <пароль>")
        sys.exit(1)

    username = sys.argv[1]
    password = sys.argv[2]

    log_separator("ДИАГНОСТИКА АВТОРИЗАЦИИ ЛК ФУ (v9 - sso/link -> orgfaru-client -> BX_ORG_FA_RU)")
    log(f"Логин: {username}")
    log(f"Пароль: {'*' * len(password)} ({len(password)} символов)")
    log(f"Время: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log(f"\nПлан:")
    log(f"  0. NextAuth signin -> state + PKCE")
    log(f"  1. Keycloak login form")
    log(f"  2. POST credentials")
    log(f"  2b. POST OTP")
    log(f"  3. NextAuth callback -> lk.fa.ru session")
    log(f"  4. Check session")
    log(f"  5. JWT via SSO + PKCE (без повторного OTP!)")
    log(f"  5b. SSO-handshake с org.fa.ru (Bitrix-сессия)")
    log(f"  5c. Исследование OAuth flow org.fa.ru (поиск client_id)")
    log(f"  5d. SSO с правильным client_id (если найден)")
    log(f"  6. Профиль + приказы + зачётка + студбилет (JWT + cookies)")

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "ru"
    })

    # 0
    signin = step0_nextauth_signin(session)
    if not signin or not signin.get("url"):
        log("Не удалось инициировать OAuth через NextAuth", "FATAL")
        sys.exit(1)

    # 1
    form = step1_load_login_form(session, signin["url"])
    if not form:
        log("Не удалось загрузить форму логина", "FATAL")
        sys.exit(1)

    # 2
    result = step2_submit_credentials(session, form, username, password)
    if not result or result["type"] == "error":
        msg = result.get("message", "?") if result else "нет ответа"
        log(f"Ошибка: {msg}", "FATAL")
        sys.exit(1)

    # 2b
    callback_location = None
    if result["type"] == "otp_form":
        log_separator("ТРЕБУЕТСЯ OTP-КОД")
        otp = input(">>> Код: ").strip()
        if not otp:
            sys.exit(1)
        otp_result = submit_otp_code(session, result["form_data"], otp)
        if not otp_result or otp_result["type"] == "error":
            log(f"OTP ошибка: {otp_result.get('message', '?') if otp_result else '?'}", "FATAL")
            sys.exit(1)
        if otp_result["type"] == "callback_redirect":
            callback_location = otp_result["location"]
        else:
            log(f"Неожиданный тип: {otp_result['type']}", "FATAL")
            sys.exit(1)
    elif result["type"] == "callback_redirect":
        callback_location = result["location"]
    else:
        log(f"Неожиданный тип: {result['type']}", "FATAL")
        sys.exit(1)

    if not callback_location:
        log("Нет callback URL", "FATAL")
        sys.exit(1)

    # 3
    if not step3_nextauth_callback(session, callback_location):
        log("Callback не удался", "FATAL")
        sys.exit(1)

    # 4
    session_data = step4_fetch_session(session)
    if not session_data:
        log("Сессия не получена", "FATAL")
        sys.exit(1)

    # 5 (SSO + PKCE -> JWT)
    token_data = step5_get_jwt_via_sso(session)

    # 5b: инициализация Bitrix-сессии на org.fa.ru
    access_token = token_data.get("access_token", "") if token_data else ""
    step5b_init_bitrix_session(session, access_token)

    # 5c: исследуем OAuth flow org.fa.ru — ищем правильный client_id
    explore_result = step5c_explore_org_fa_ru_auth(session, access_token)
    target_client_id = ""
    target_redirect_uri = ""
    if explore_result and explore_result.get("keycloak_urls"):
        from urllib.parse import parse_qs as _pqs
        parsed = urlparse(explore_result["keycloak_urls"][0])
        params = _pqs(parsed.query)
        target_client_id = params.get("client_id", [""])[0]
        target_redirect_uri = params.get("redirect_uri", [""])[0]
        log(f"\n>>> Из 5c: target_client_id={target_client_id}, target_redirect_uri={target_redirect_uri}")

    # 5d: если нашли другой client_id — делаем SSO с ним
    new_token_data = None
    if target_client_id and target_client_id != CLIENT_ID:
        new_token_data = step5d_sso_with_target_client(session, target_client_id, target_redirect_uri)
        if new_token_data and new_token_data.get("access_token"):
            log(f"\n>>> Используем НОВЫЙ JWT (с правильным client_id) для шага 6")
            token_data = new_token_data
            access_token = token_data["access_token"]

    # 6
    profile_data = step6_fetch_profile(session, session_data, token_data)

    # ИТОГ
    log_separator("ИТОГ")
    user = session_data.get("user", {})
    log(f"lk.fa.ru сессия: ДА")
    log(f"  {user.get('name', '?')} / {user.get('email', '?')}")
    log(f"  userId: {session_data.get('userId', '?')}")
    log(f"JWT access_token: {'ДА' if token_data else 'НЕТ'}")
    if token_data:
        log(f"  expires_in: {token_data.get('expires_in', '?')}с")
    log(f"org.fa.ru профиль: {'ДА' if profile_data.get('profile') else 'НЕТ'}")
    log(f"Приказы: {'ДА (' + str(len(profile_data.get('orders', []))) + ' шт)' if profile_data.get('orders') else 'НЕТ'}")
    log(f"Зачётная книжка: {'ДА' if profile_data.get('marks') else 'НЕТ'}")
    log(f"Студенческий билет: {'ДА' if profile_data.get('student_card') else 'НЕТ'}")
    log(f"\nВсе куки ({len(session.cookies)} шт):")
    for c in session.cookies:
        log(f"  {c.name} [domain={c.domain}]")
    log("\nГотово.")


if __name__ == "__main__":
    main()