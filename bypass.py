import threading
import time
import os
from mitmproxy import http, ctx
from aes_utils import AESUtils
from proto_utils import ProtobufUtils
import LoginRes_pb2
import LoginResNew_pb2
import Login_pb2
import binascii
from mitmproxy.tools.main import mitmdump
import random
import requests

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 6268
UID_FILE = "uid.txt"
CACHE_REFRESH_INTERVAL = 300
FIREBASE_DATABASE_URL = "put realtime firebase databaseurl"
DEFAULT_SECRETS = [""] #secret from the site admin.html
WHITELIST_MSG = "[ffffff] UID NOT AUTHORIZED\n\n[FFFFFF]UID: {uid} ."


aes_utils = AESUtils()
proto_utils = ProtobufUtils()

uid_cache = set()
cache_lock = threading.Lock()
last_cache_refresh = 0
cache_initialized = False

firebase_initialized = False
paid_uids_cache = set()
free_uids_cache = {}
secrets_cache = {}

def fetch_uids_from_file():
    global uid_cache, last_cache_refresh, cache_initialized
    try:
        ctx.log.debug(f"Loading from {UID_FILE}")
        new_uid_cache = set()
        if os.path.exists(UID_FILE):
            with open(UID_FILE, 'r') as file:
                for line in file:
                    uid = line.strip()
                    if uid and uid.isdigit():
                        new_uid_cache.add(uid)
        if not new_uid_cache:
            ctx.log.debug("No UIDs found")
        with cache_lock:
            uid_cache.clear()
            uid_cache.update(new_uid_cache)
            last_cache_refresh = time.time()
            cache_initialized = True
        ctx.log.info(f"Loaded {len(new_uid_cache)} UIDs from file")
        return True
    except Exception as e:
        ctx.log.error(f"File loading error: {e}")
        with cache_lock:
            cache_initialized = True
        return False

def initialize_firebase():
    global firebase_initialized
    if firebase_initialized:
        return True
    try:
        response = requests.get(FIREBASE_DATABASE_URL, timeout=10)
        if response.status_code == 200:
            firebase_initialized = True
            return True
        else:
            ctx.log.error(f"Firebase API returned status {response.status_code}")
            return False
    except Exception as e:
        ctx.log.error(f"Firebase connection error: {e}")
        return False

def fetch_uids_from_firebase():
    global paid_uids_cache, free_uids_cache, secrets_cache, cache_initialized
    if not initialize_firebase():
        ctx.log.error("Firebase not initialized")
        return False
    try:
        users_url = FIREBASE_DATABASE_URL.replace('.json', '/users.json')
        response = requests.get(users_url, timeout=30)
        if response.status_code != 200:
            ctx.log.error(f"Firebase API error: {response.status_code}")
            return False
        snapshot = response.json()
        if not snapshot:
            ctx.log.debug("No users found")
            return False
        new_paid_uids = set()
        new_free_uids = {}
        new_secrets = {}
        for user_id, user_data in snapshot.items():
            uids = user_data.get('uids', [])
            if isinstance(uids, list):
                for uid_data in uids:
                    if isinstance(uid_data, dict) and 'uid' in uid_data:
                        new_paid_uids.add(str(uid_data['uid']))
                    elif isinstance(uid_data, str):
                        new_paid_uids.add(uid_data)
            freeuids = user_data.get('freeuids', [])
            user_secrets = user_data.get('secrets', [])
            if isinstance(user_secrets, str):
                user_secrets = [user_secrets]
            elif not isinstance(user_secrets, list):
                user_secrets = []
            legacy_secret = user_data.get('secret')
            if legacy_secret and legacy_secret not in user_secrets:
                user_secrets.append(legacy_secret)
            for secret in user_secrets:
                if secret and freeuids:
                    if secret not in new_free_uids:
                        new_free_uids[secret] = set()
                    for uid in freeuids:
                        if isinstance(uid, str):
                            new_free_uids[secret].add(uid)
            all_user_secrets = set(user_secrets + DEFAULT_SECRETS)
            new_secrets[user_id] = all_user_secrets
        with cache_lock:
            paid_uids_cache.clear()
            paid_uids_cache.update(new_paid_uids)
            free_uids_cache.clear()
            free_uids_cache.update(new_free_uids)
            secrets_cache.clear()
            secrets_cache.update(new_secrets)
            cache_initialized = True
            last_cache_refresh = time.time()
        total_secrets = sum(len(secrets) for secrets in new_secrets.values())
        ctx.log.info(f"Loaded {len(new_paid_uids)} paid UIDs, {total_secrets} secrets from Firebase")
        return True
    except Exception as e:
        ctx.log.error(f"Firebase loading error: {e}")
        with cache_lock:
            cache_initialized = True
        return False

def check_uid_exists(uid: str, client_ip: str = None) -> tuple[bool, bool]:
    uid = str(uid).strip()

    if uid == "0":
        return True, False

    with cache_lock:
        if not cache_initialized:
            ctx.log.warn(f"Cache not initialized, temporarily allowing UID {uid}")
            return True, False

        needs_refresh = (not uid_cache or time.time() - last_cache_refresh > CACHE_REFRESH_INTERVAL)
        is_regular_uid = uid in uid_cache

        is_paid_uid = uid in paid_uids_cache
        is_free_uid = False
        for secret_uids in free_uids_cache.values():
            if uid in secret_uids:
                is_free_uid = True
                break
        is_firebase_uid = is_paid_uid or is_free_uid

        # Use both regular file UIDs and Firebase UIDs
        is_authorized = is_regular_uid or is_firebase_uid

    if needs_refresh:
        ctx.log.debug("Scheduling background cache refresh")
        threading.Thread(target=fetch_uids_from_file, daemon=True).start()

    uid_type = "PAID" if is_paid_uid else ("FREE" if is_free_uid else ("FILE" if is_regular_uid else "UNKNOWN"))
    ctx.log.info(f"{'✅' if is_authorized else '❌'} {uid_type} UID {uid}")
    return is_authorized, False

def validate_free_uid_access(uid: str, secret: str) -> bool:
    with cache_lock:
        if secret in free_uids_cache and uid in free_uids_cache[secret]:
            return True
        return False

def get_client_ip(flow: http.HTTPFlow) -> str:
    try:
        if hasattr(flow, 'client_conn') and hasattr(flow.client_conn, 'address'):
            return flow.client_conn.address[0]
        return "unknown"
    except:
        return "unknown"

def get_spoofed_device_info():
    android_versions = [
        "Android OS 15 / API-35 (TP1A.220905.001/U.R4T2.1c822c2_1_3)",
        "Android OS 14 / API-34 (UP1A.231005.007)",
        "Android OS 13 / API-33 (TQ3A.230805.001)",
        "Android OS 12 / API-31 (SP1A.210812.016)"
    ]
    device_models = [
        "OnePlus CPH2613",
        "Samsung SM-G998B",
        "Xiaomi 2211133G",
        "Google Pixel 7 Pro"
    ]
    carriers = ["Ncell", "Verizon", "AT&T", "T-Mobile", "Vodafone"]
    return {
        'game_name': "free fire",
        'some_flag': 1,
        'os_info': random.choice(android_versions),
        'device_type': "Handheld",
        'carrier': random.choice(carriers),
        'connection': "WIFI",
        'screen_width': 2412,
        'screen_height': 1080,
        'dpi': "480",
        'cpu_info': "ARM64 FP ASIMD AES | 5260 | 8",
        'total_ram': random.randint(6000, 12000),
        'gpu': "Adreno (TM) 720",
        'gpu_version': "OpenGL ES 3.2 V@0676.65 (GIT@d4072932f4, Ie89cf9a769, 1730731391) (Date:11/04/24)",
        'google_account': f"Google|{binascii.hexlify(os.urandom(16)).decode()}",
        'language': "en",
        'device_category': "Handheld",
        'device_model': random.choice(device_models),
        'unknown30': 1,
        'carrier2': random.choice(carriers),
        'connection2': "WIFI",
        'session_id': binascii.hexlify(os.urandom(16)).decode(),
        'val60': 102783,
        'val61': 50899,
        'val62': 743,
        'val64': 51027,
        'val65': 102783,
        'val66': 51027,
        'val67': 102783,
        'val73': 3,
        'lib_path': "/data/app/~~jHEWM3xbT9VVYUy8eZmOiA==/com.dts.freefireth-B_KiZCdyGM6n3eXaOUmALA==/lib/arm64",
        'val76': 1,
        'apk_signature': "2087f61c19f57f2af4e7feff0b24d9d9|/data/app/~~jHEWM3xbT9VVYUy8eZmOiA==/com.dts.freefireth-B_KiZCdyGM6n3eXaOUmALA==/base.apk",
        'val78': 3,
        'val79': 2,
        'arch': "64",
        'version_code': "2019118695",
        'gfx_renderer': "OpenGLES2",
        'max_texture_size': 16383,
        'cores': 8,
        'unknown92': 2950,
        'platform': "android",
        'signature': "KqsHTxnXXUCG8sxXFVB2j0AUs3+0cvY/WgLeTdfTE/KPENeJPpny2EPnJDs8C8cBVMcd1ApAoCmM9MhzDDXabISdK31SKSFSr06eVCZ4D2Yj/C7G",
        'total_storage': 111117,
        'refresh_rate_json': '{"cur_rate":[60,90,120]}',
        'unknown97': 1,
        'unknown98': 1,
        'raw_bytes': b"\x13RFC\x07\x0e\\Q1"
    }

class LoginInterceptor:
    def load(self, loader):
        ctx.log.info(f"Interceptor loaded on {LISTEN_HOST}:{LISTEN_PORT}")
        threading.Thread(target=self._load_uids_background, daemon=True).start()

    def _load_uids_background(self):
        try:
            if not fetch_uids_from_firebase():
                fetch_uids_from_file()
        except Exception as e:
            ctx.log.error(f"Background loading error: {e}")
            try:
                fetch_uids_from_file()
            except Exception as fe:
                ctx.log.error(f"Fallback loading error: {fe}")

    def request(self, flow: http.HTTPFlow) -> None:
        try:
            if not flow.request.content:
                return
            try:
                client_ip = get_client_ip(flow)
                decrypted = aes_utils.decrypt_aes_cbc(flow.request.content)
                try:
                    login_req = proto_utils.decode_protobuf(decrypted, LoginRes_pb2.NewLoginReq)
                    device_info = get_spoofed_device_info()
                    for field, value in device_info.items():
                        if hasattr(login_req, field):
                            setattr(login_req, field, value)
                    ctx.log.info(f"Spoofed device info from {client_ip}")
                    flow.metadata["is_login_request"] = True
                    serialized = proto_utils.encode_protobuf(login_req)
                    encrypted = aes_utils.encrypt_aes_cbc(serialized)
                    flow.request.content = encrypted
                    flow.request.headers["Content-Length"] = str(len(flow.request.content))
                except Exception as e:
                    ctx.log.debug(f"Not login: {e}")
                    flow.metadata["is_login_request"] = False
            except Exception as de:
                ctx.log.debug(f"Decrypt failed: {de}")
                # Not encrypted, skip
                pass
            # Check if it's MajorLogin
            if '/majorlogin' in flow.request.path.lower():
                flow.metadata["is_major_login"] = True
                ctx.log.info("Detected MajorLogin request")
            else:
                flow.metadata["is_major_login"] = False
        except Exception as e:
            ctx.log.error(f"Request error: {e}")

    def response(self, flow: http.HTTPFlow) -> None:
        try:
            if not flow.response.content:
                return
            client_ip = get_client_ip(flow)
            self._handle_login_response(flow, client_ip)
        except Exception as e:
            ctx.log.error(f"Response error: {e}")

    def _handle_login_response(self, flow: http.HTTPFlow, client_ip: str) -> None:
        # Only auth UID for login responses
        if not flow.metadata.get("is_login_request", False):
            return

        # Force cache initialization if not done
        if not cache_initialized:
            try:
                if not fetch_uids_from_firebase():
                    fetch_uids_from_file()
            except Exception as load_e:
                ctx.log.error(f"Force load error: {load_e}")

        try:
            # Method 1: Extract UID from login response
            uid_found = False
            try:
                decoded_body = proto_utils.decode_protobuf(flow.response.content, Login_pb2.getUID)
                if hasattr(decoded_body, 'uid'):
                    actual_uid = str(decoded_body.uid)
                    ctx.log.info(f"SUCCESS: UID {actual_uid} from getUID")
                    uid_found = True
            except Exception as uid_e:
                ctx.log.info(f"getUID decode failed: {uid_e}")
            if not uid_found:
                try:
                    decoded_body = proto_utils.decode_protobuf(flow.response.content, LoginResNew_pb2.MajorLoginRes)
                    if hasattr(decoded_body, 'uid'):
                        actual_uid = str(decoded_body.uid)
                        ctx.log.info(f"SUCCESS: UID {actual_uid} from MajorLoginRes")
                        uid_found = True
                except Exception as ml_e:
                    ctx.log.info(f"MajorLoginRes decode failed: {ml_e}")
            if not uid_found:
                try:
                    decoded_body = proto_utils.decode_protobuf(flow.response.content, LoginResNew_pb2.LoginRes)
                    if hasattr(decoded_body, 'uid'):
                        actual_uid = str(decoded_body.uid)
                        ctx.log.info(f"SUCCESS: UID {actual_uid} from LoginRes")
                        uid_found = True
                except Exception as lr_e:
                    ctx.log.info(f"LoginRes decode failed: {lr_e}")
            if not uid_found:
                ctx.log.info("No UID found in response, allowing login")
                return
            is_authorized, _ = check_uid_exists(actual_uid, client_ip)
            if flow.metadata.get("is_major_login", False) and not is_authorized:
                ctx.log.warn(f"Blocked unauthorized UID {actual_uid}")
                error_message = WHITELIST_MSG.format(uid=actual_uid).encode()
                flow.response.content = error_message
                flow.response.status_code = 400
                flow.response.headers["Content-Type"] = "text/plain"
                return
            ctx.log.info(f"ALLOWED: UID {actual_uid}")
            return

        except Exception as e:
            ctx.log.error(f"Critical login response error: {e}")

addons = [LoginInterceptor()]

if __name__ == "__main__":
    import sys
    sys.argv = [
        "mitmdump",
        "-s", __file__,
        "-p", str(LISTEN_PORT),
        "--listen-host", LISTEN_HOST,
        "--set", "block_global=false",
        "--set", "ssl_insecure=true",
    ]
    print(f"MITM proxy on {LISTEN_HOST}:{LISTEN_PORT}")
    print(f"UID file: {UID_FILE}")
    try:
        mitmdump()
    except KeyboardInterrupt:
        print("Shutdown...")
