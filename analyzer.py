import sqlite3, os, re, io, csv, math, time, tarfile, threading, ipaddress, requests, hmac, hashlib, secrets, json
from collections import Counter
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, Response
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get('SQLITE_PATH') or os.path.join(BASE_DIR, 'security.db')
app = Flask(__name__)
KST = ZoneInfo('Asia/Seoul')


def required_env(name):
    value = os.environ.get(name, '').strip()
    if not value:
        raise RuntimeError(f'환경변수 {name}가 설정되지 않았습니다. Render Environment에 추가하세요.')
    return value

SECRET_KEY = required_env('SECRET_KEY')
ENROLL_KEY = required_env('ENROLL_KEY')
REAUTH_PIN = required_env('REAUTH_PIN')
ADMIN_PASSWORD = required_env('ADMIN_PASSWORD')
if not re.fullmatch(r'\d{4}', REAUTH_PIN):
    raise RuntimeError('REAUTH_PIN은 숫자 4자리여야 합니다.')
VWORLD_KEY = os.environ.get('VWORLD_KEY', '')
TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN', '')
TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '')
DISCORD_WEBHOOK_URL = os.environ.get('DISCORD_WEBHOOK_URL', '')
BREVO_API_KEY = os.environ.get('BREVO_API_KEY', '')
OTP_EMAIL = os.environ.get('OTP_EMAIL', '')
MAXMIND_ACCOUNT_ID = os.environ.get('MAXMIND_ACCOUNT_ID', '')
MAXMIND_LICENSE_KEY = os.environ.get('MAXMIND_LICENSE_KEY', '')
GEOLITE2_PATH = os.environ.get('GEOLITE2_PATH') or '/tmp/GeoLite2-City.mmdb'
RETENTION_DAYS = int(os.environ.get('RETENTION_DAYS', '90') or 90)
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL:
    import psycopg2

WEIGHTS = {
    'TZ_MISMATCH': 60,
    'IMPOSSIBLE_TRAVEL': 60,
    'FP_CHANGED': 40,
    'WEBRTC_LEAK': 40,
    'UNKNOWN_DEVICE': 30,
    'LANG_MISMATCH': 20,
    'PROXY_IP': 20,
    'HOSTING_IP': 15,
    'UNUSUAL_HOUR': 15,
    'BLOCKED': 100,
}
REASON_NAMES = {
    'TZ_MISMATCH': '시간대 불일치',
    'IMPOSSIBLE_TRAVEL': '불가능한 이동',
    'FP_CHANGED': '기기 지문 변경',
    'WEBRTC_LEAK': 'WebRTC 실제 IP 유출',
    'UNKNOWN_DEVICE': '미등록 기기',
    'LANG_MISMATCH': '언어·국가 불일치',
    'PROXY_IP': '프록시·VPN IP',
    'HOSTING_IP': '데이터센터 IP',
    'UNUSUAL_HOUR': '평소와 다른 접속 시간',
    'BLOCKED': '차단된 IP·기기',
}
LANG_COUNTRY = {'ko': 'KR', 'ja': 'JP', 'zh': 'CN', 'vi': 'VN', 'th': 'TH'}
SUSPICIOUS_LINE = 30
REAUTH_LINE = 60
ADMIN_FAIL_LIMIT = 5
ADMIN_FAIL_MINUTES = 15
REAUTH_MINUTES = 5
REAUTH_MAX_TRY = 3
FAIL_LIMIT = 6
FAIL_WINDOW_HOURS = 24
TRAVEL_MIN_KM = 500
TRAVEL_MAX_KMH = 900
HABIT_MIN_LOGS = 5
GEO_CACHE_SECONDS = 1800
DEFAULT_LAT, DEFAULT_LNG = 35.8242, 127.1480
UNKNOWN_PLACE = '위치 확인 불가'


def get_conn():
    if DATABASE_URL:
        return psycopg2.connect(DATABASE_URL)
    return sqlite3.connect(DB_PATH)

def q(sql):
    return sql.replace('?', '%s') if DATABASE_URL else sql

def id_col():
    return 'id' if DATABASE_URL else 'rowid'

def now_kst():
    return datetime.now(KST)

def fmt_time(dt):
    return dt.strftime('%Y-%m-%d %H:%M:%S')

def parse_time(ts):
    return datetime.strptime(ts, '%Y-%m-%d %H:%M:%S').replace(tzinfo=KST)

def clip(v, n):
    return str(v or '')[:n]


def client_ip():
    for h in ('CF-Connecting-IP', 'True-Client-IP'):
        v = request.headers.get(h)
        if v:
            return v.strip()[:64]
    return request.remote_addr or ''


def public_ips(values, limit=5):
    out = []
    for v in values if isinstance(values, list) else []:
        try:
            a = ipaddress.ip_address(str(v).strip())
        except ValueError:
            continue
        if a.is_global and str(a) not in out:
            out.append(str(a))
        if len(out) >= limit:
            break
    return out


def load_tz_country():
    table = {}
    paths = ['/usr/share/zoneinfo/zone.tab']
    try:
        import tzdata
        paths.append(os.path.join(os.path.dirname(tzdata.__file__), 'zoneinfo', 'zone.tab'))
    except ImportError:
        pass
    for path in paths:
        try:
            with open(path, encoding='utf-8') as f:
                for line in f:
                    if line.startswith('#'):
                        continue
                    cols = line.rstrip('\n').split('\t')
                    if len(cols) >= 3:
                        table[cols[2]] = cols[0]
        except OSError:
            pass
    return table

TZ_COUNTRY = load_tz_country()


def sign(text):
    return hmac.new(SECRET_KEY.encode(), text.encode(), hashlib.sha256).hexdigest()[:32]

def make_device_token(fp, did=None):
    did = did or secrets.token_hex(8)
    return f"{did}.{fp}.{sign(did + '.' + fp)}"

def read_device_token(token):
    try:
        did, fp, sig = token.split('.')
        if hmac.compare_digest(sig, sign(did + '.' + fp)):
            return did, fp
    except Exception:
        pass
    return None, None

def fingerprint(data):
    ua = re.sub(r'[\d._]+', '', clip(data.get('ua'), 300))
    raw = '|'.join([ua] + [clip(data.get(k), 300) for k in ('res', 'plat', 'fp')])
    return hashlib.sha256(raw.encode()).hexdigest()[:16]

def legacy_fingerprint(data):
    raw = '|'.join(clip(data.get(k), 300) for k in ('ua', 'res', 'plat', 'fp'))
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _send(url, **kwargs):
    try:
        requests.post(url, timeout=5, **kwargs)
    except Exception as e:
        print(f"[알림 전송 실패] {e}")

def notify(text):
    jobs = []
    if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
        jobs.append((f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                     {'json': {'chat_id': TELEGRAM_CHAT_ID, 'text': text}}))
    if DISCORD_WEBHOOK_URL:
        jobs.append((DISCORD_WEBHOOK_URL, {'json': {'content': text[:1900]}}))
    for url, kw in jobs:
        threading.Thread(target=_send, args=(url,), kwargs=kw, daemon=True).start()

def otp_channels():
    ch = []
    if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
        ch.append('텔레그램')
    if BREVO_API_KEY and OTP_EMAIL:
        ch.append('이메일')
    return ch

def send_otp(code, place):
    text = f"[Honey-Trap] 재인증 번호 {code} ({REAUTH_MINUTES}분 안에 입력)\n접속 위치: {place}\n본인이 아니면 입력하지 마세요."
    if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
        threading.Thread(target=_send, args=(f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",),
                         kwargs={'json': {'chat_id': TELEGRAM_CHAT_ID, 'text': text}}, daemon=True).start()
    if BREVO_API_KEY and OTP_EMAIL:
        body = {'sender': {'name': 'Honey-Trap', 'email': OTP_EMAIL}, 'to': [{'email': OTP_EMAIL}],
                'subject': f'[Honey-Trap] 재인증 번호 {code}', 'textContent': text}
        threading.Thread(target=_send, args=('https://api.brevo.com/v3/smtp/email',),
                         kwargs={'json': body, 'headers': {'api-key': BREVO_API_KEY}}, daemon=True).start()

def reasons_text(reasons):
    return '\n'.join(f"+{r['points']} {REASON_NAMES.get(r['code'], r['code'])}: {r['detail']}" for r in reasons)


_geo_cache = {}
_geolite = {'reader': None, 'status': '미설정'}


def _open_geolite():
    try:
        import geoip2.database
    except ImportError:
        _geolite['status'] = 'geoip2 패키지 없음'
        return
    try:
        if not os.path.exists(GEOLITE2_PATH):
            if not (MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY):
                _geolite['status'] = 'MaxMind 키 없음'
                return
            _geolite['status'] = '다운로드 중'
            url = 'https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz'
            r = requests.get(url, auth=(MAXMIND_ACCOUNT_ID, MAXMIND_LICENSE_KEY), timeout=120)
            r.raise_for_status()
            with tarfile.open(fileobj=io.BytesIO(r.content), mode='r:gz') as tar:
                member = next(m for m in tar.getmembers() if m.name.endswith('.mmdb'))
                with open(GEOLITE2_PATH + '.part', 'wb') as out:
                    out.write(tar.extractfile(member).read())
            os.replace(GEOLITE2_PATH + '.part', GEOLITE2_PATH)
        _geolite['reader'] = geoip2.database.Reader(GEOLITE2_PATH)
        _geolite['status'] = '사용 중'
        print('[GeoLite2] 로컬 DB 사용')
    except Exception as e:
        _geolite['status'] = f'오류: {e}'
        print(f'[GeoLite2 FAIL] {e}')

threading.Thread(target=_open_geolite, daemon=True).start()


def geolite_lookup(ip):
    reader = _geolite['reader']
    if reader is None:
        return None
    try:
        r = reader.city(ip)
    except Exception:
        return None
    if r.location.latitude is None:
        return None
    return {'country': r.country.name, 'countryCode': r.country.iso_code,
            'regionName': r.subdivisions.most_specific.name, 'city': r.city.name,
            'lat': r.location.latitude, 'lon': r.location.longitude, 'timezone': r.location.time_zone,
            'proxy': False, 'hosting': False, 'source': 'GeoLite2'}

def lookup_ip(ip):
    hit = _geo_cache.get(ip)
    if hit and time.time() - hit[0] < GEO_CACHE_SECONDS:
        return hit[1]

    local = geolite_lookup(ip)
    geo = None
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,lat,lon,timezone,proxy,hosting"
        j = requests.get(url, timeout=4).json()
        if j.get('status') == 'success':
            geo = j
        else:
            print(f"[ip-api FAIL] {j}")
    except Exception as e:
        print(f"[ip-api FAIL] {e}")

    if geo is None:
        try:
            j = requests.get(f"https://ipwho.is/{ip}", timeout=4).json()
            if j.get('success'):
                sec = j.get('security') or {}
                geo = {'country': j.get('country'), 'countryCode': j.get('country_code'),
                       'regionName': j.get('region'), 'city': j.get('city'),
                       'lat': j.get('latitude'), 'lon': j.get('longitude'),
                       'timezone': (j.get('timezone') or {}).get('id'),
                       'proxy': bool(sec.get('vpn') or sec.get('proxy')), 'hosting': bool(sec.get('hosting'))}
            else:
                print(f"[ipwho FAIL] {j}")
        except Exception as e:
            print(f"[ipwho FAIL] {e}")

    if local:
        if geo:
            local['proxy'], local['hosting'] = bool(geo.get('proxy')), bool(geo.get('hosting'))
        geo = local
    if geo is not None:
        _geo_cache[ip] = (time.time(), geo)
    return geo


def distance_km(lat1, lng1, lat2, lng2):
    r = math.radians
    h = math.sin(r(lat2 - lat1) / 2) ** 2 + math.cos(r(lat1)) * math.cos(r(lat2)) * math.sin(r(lng2 - lng1) / 2) ** 2
    return 2 * 6371 * math.asin(math.sqrt(h))


def travel_text(km, minutes):
    hours = max(minutes / 60, 1 / 60)
    speed = km / hours
    if km < TRAVEL_MIN_KM or speed <= TRAVEL_MAX_KMH:
        return None
    return f"직전 접속 위치에서 {km:,.0f}km를 {hours * 60:,.0f}분 만에 이동 (시속 {speed:,.0f}km)"

def check_travel(cur, device, geo, now):
    if not device or not geo or geo.get('lat') is None:
        return None
    cur.execute(q(f"SELECT lat, lng, timestamp FROM logs WHERE device=? AND city<>? AND status='SECURE' AND simulated=0 ORDER BY {id_col()} DESC LIMIT 1"), (device, UNKNOWN_PLACE))
    row = cur.fetchone()
    if not row or row[0] is None:
        return None
    km = distance_km(float(row[0]), float(row[1]), float(geo['lat']), float(geo['lon']))
    return travel_text(km, (now - parse_time(row[2])).total_seconds() / 60)


def check_hour(cur, device, now):
    if not device or device.startswith('c-'):
        return None
    cur.execute(q(f"SELECT timestamp FROM logs WHERE device=? AND status='SECURE' AND simulated=0 ORDER BY {id_col()} DESC LIMIT 200"), (device,))
    hours = [parse_time(r[0]).hour for r in cur.fetchall()]
    if len(hours) < HABIT_MIN_LOGS:
        return None
    h = now.hour
    if any(min(abs(h - x), 24 - abs(h - x)) <= 1 for x in hours):
        return None
    return f"평소 접속 시간대가 아닌 {h}시에 접속 (최근 정상 접속 {len(hours)}건 기준)"


def check_lang(lang, geo):
    if not lang or not geo or not geo.get('countryCode'):
        return None
    parts = lang.replace('_', '-').split('-')
    region = parts[-1].upper() if len(parts) > 1 and len(parts[-1]) == 2 else LANG_COUNTRY.get(parts[0].lower())
    if not region or region == geo['countryCode']:
        return None
    return f"브라우저 언어 {lang} / IP 국가 {geo['countryCode']}"


def check_webrtc(ip, rtc_ips):
    try:
        conn_ip = ipaddress.ip_address(ip)
    except ValueError:
        return None, None
    for v in rtc_ips:
        a = ipaddress.ip_address(v)
        if a.version == conn_ip.version and a != conn_ip:
            return v, lookup_ip(v)
    return None, None


def fail_count(cur, keys, hours=FAIL_WINDOW_HOURS):
    since = fmt_time(now_kst() - timedelta(hours=hours))
    counts = [0]
    for k in keys:
        if k:
            cur.execute(q("SELECT COUNT(*) FROM reauth_fail WHERE fail_key=? AND ts > ?"), (k, since))
            counts.append(cur.fetchone()[0])
    return max(counts)

def manual_blocked(cur, keys):
    for k in keys:
        if k:
            cur.execute(q("SELECT reason FROM manual_block WHERE block_key=?"), (k,))
            row = cur.fetchone()
            if row:
                return row[0] or '관리자가 차단'
    return None

def add_fail(cur, keys):
    for k in keys:
        if k:
            cur.execute(q("INSERT INTO reauth_fail (fail_key, ts) VALUES (?,?)"), (k, fmt_time(now_kst())))


_setting_cache = {'t': 0, 'reauth_line': REAUTH_LINE}

def reauth_line():
    if time.time() - _setting_cache['t'] > 10:
        try:
            conn = get_conn(); cur = conn.cursor()
            cur.execute(q("SELECT value FROM settings WHERE skey=?"), ('reauth_line',))
            row = cur.fetchone()
            conn.close()
            _setting_cache['reauth_line'] = int(row[0]) if row else REAUTH_LINE
        except Exception as e:
            print(f'[설정 읽기 실패] {e}')
        _setting_cache['t'] = time.time()
    return _setting_cache['reauth_line']


def calc_score(browser_tz, geo, device_state, travel=None, blocked=None, lang=None, leak=None, unusual=None, line=None):
    reasons = []
    if blocked:
        reasons.append(('BLOCKED', blocked))
    if geo:
        ip_tz = geo.get('timezone')
        if ip_tz and ip_tz != browser_tz:
            same_country = TZ_COUNTRY.get(browser_tz) and TZ_COUNTRY.get(browser_tz) == geo.get('countryCode')
            if not same_country:
                reasons.append(('TZ_MISMATCH', f"브라우저 {browser_tz} / IP {ip_tz}"))
        if geo.get('proxy'):
            reasons.append(('PROXY_IP', '프록시/VPN 대역 IP'))
        if geo.get('hosting'):
            reasons.append(('HOSTING_IP', '데이터센터 IP'))
    if travel:
        reasons.append(('IMPOSSIBLE_TRAVEL', travel))
    if leak:
        reasons.append(('WEBRTC_LEAK', leak))
    if lang:
        reasons.append(('LANG_MISMATCH', lang))
    if unusual:
        reasons.append(('UNUSUAL_HOUR', unusual))
    if device_state == 'UNKNOWN':
        reasons.append(('UNKNOWN_DEVICE', '등록되지 않은 기기'))
    elif device_state == 'CHANGED':
        reasons.append(('FP_CHANGED', '등록 기기의 지문 값이 달라짐'))

    reasons = [{'code': c, 'points': WEIGHTS[c], 'detail': d} for c, d in reasons]
    score = min(100, sum(r['points'] for r in reasons))
    if score >= (line or reauth_line()):
        status = 'INTRUSION'
    elif score >= SUSPICIOUS_LINE:
        status = 'SUSPICIOUS'
    else:
        status = 'SECURE'
    return score, status, reasons


def init_db():
    cols = (('status', 'TEXT'), ('reasons', 'TEXT'), ('verified', 'INTEGER DEFAULT 0'), ('device', 'TEXT'),
            ('country', 'TEXT'), ('lang', 'TEXT'), ('simulated', 'INTEGER DEFAULT 0'))
    conn = get_conn(); cur = conn.cursor()
    if DATABASE_URL:
        cur.execute('''CREATE TABLE IF NOT EXISTS logs
                       (id SERIAL PRIMARY KEY, ip TEXT, ua TEXT, res TEXT, tz TEXT, lat DOUBLE PRECISION, lng DOUBLE PRECISION,
                        city TEXT, score INTEGER, platform TEXT, timestamp TEXT)''')
        for col, typ in cols:
            cur.execute(f'ALTER TABLE logs ADD COLUMN IF NOT EXISTS {col} {typ}')
    else:
        cur.execute('''CREATE TABLE IF NOT EXISTS logs
                       (ip TEXT, ua TEXT, res TEXT, tz TEXT, lat REAL, lng REAL, city TEXT, score INTEGER, platform TEXT, timestamp TEXT)''')
        have = [r[1] for r in cur.execute('PRAGMA table_info(logs)').fetchall()]
        for col, typ in cols:
            if col not in have:
                cur.execute(f'ALTER TABLE logs ADD COLUMN {col} {typ}')
    cur.execute("UPDATE logs SET simulated=0 WHERE simulated IS NULL")
    cur.execute('''CREATE TABLE IF NOT EXISTS reauth
                   (token TEXT PRIMARY KEY, log_id INTEGER, fp TEXT, expires TEXT,
                    attempts INTEGER DEFAULT 0, done INTEGER DEFAULT 0)''')
    if DATABASE_URL:
        cur.execute('ALTER TABLE reauth ADD COLUMN IF NOT EXISTS otp_hash TEXT')
    else:
        if 'otp_hash' not in [r[1] for r in cur.execute('PRAGMA table_info(reauth)').fetchall()]:
            cur.execute('ALTER TABLE reauth ADD COLUMN otp_hash TEXT')
    cur.execute('CREATE TABLE IF NOT EXISTS reauth_fail (fail_key TEXT, ts TEXT)')
    cur.execute('CREATE TABLE IF NOT EXISTS manual_block (block_key TEXT PRIMARY KEY, reason TEXT, ts TEXT)')
    cur.execute('CREATE TABLE IF NOT EXISTS settings (skey TEXT PRIMARY KEY, value TEXT)')
    conn.commit(); conn.close()
init_db()


def get_detail_address(lng, lat):
    if not VWORLD_KEY:
        return None
    try:
        url = f"https://api.vworld.kr/req/address?service=address&request=getAddress&version=2.0&crs=epsg:4326&point={lng},{lat}&format=json&type=both&key={VWORLD_KEY}"
        r = requests.get(url, timeout=4).json()
        result = r.get('response',{}).get('result',[])
        if result and result[0].get('text'):
            return result[0]['text']
    except Exception as e:
        print(f"[VWorld FAIL] {e}")
    return None


def place_of(geo, vpn, use_vworld=True):
    if not geo or geo.get('lat') is None:
        return DEFAULT_LAT, DEFAULT_LNG, UNKNOWN_PLACE
    lat, lng = geo.get('lat'), geo.get('lon')
    name = ' '.join(x for x in (geo.get('country'), geo.get('regionName'), geo.get('city')) if x)
    if vpn:
        short = ', '.join(x for x in (geo.get('city'), geo.get('country')) if x) or name
        return lat, lng, f"{short} (VPN 의심: {geo.get('timezone')})"
    if use_vworld and geo.get('countryCode') == 'KR':
        addr = get_detail_address(lng, lat)
        if addr:
            return lat, lng, addr
    return lat, lng, name or UNKNOWN_PLACE


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        key = 'admin:' + client_ip()
        hours = ADMIN_FAIL_MINUTES / 60
        conn = get_conn(); cur = conn.cursor()
        if fail_count(cur, [key], hours) >= ADMIN_FAIL_LIMIT:
            conn.close()
            return Response(f'로그인 실패가 반복되어 {ADMIN_FAIL_MINUTES}분 동안 잠겼습니다.', 429,
                            {'Content-Type': 'text/plain; charset=utf-8', 'Retry-After': str(ADMIN_FAIL_MINUTES * 60)})
        auth = request.authorization
        if not auth or not hmac.compare_digest((auth.password or '').encode(), ADMIN_PASSWORD.encode()):
            if auth:
                add_fail(cur, [key])
                conn.commit()
                if fail_count(cur, [key], hours) >= ADMIN_FAIL_LIMIT:
                    notify(f"🔐 [Honey-Trap] 관리자 로그인 {ADMIN_FAIL_LIMIT}회 실패\nIP {client_ip()} · {ADMIN_FAIL_MINUTES}분 잠금")
            conn.close()
            return Response('관리자 인증이 필요합니다.', 401,
                            {'WWW-Authenticate': 'Basic realm="honey-trap admin"', 'Content-Type': 'text/plain; charset=utf-8'})
        conn.close()
        return f(*args, **kwargs)
    return wrapper


def same_origin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        origin = request.headers.get('Origin', '')
        if request.headers.get('X-Requested-With') != 'honey-trap' or (origin and origin != request.host_url.rstrip('/')):
            return jsonify({'error': '허용되지 않은 요청입니다.'}), 403
        return f(*args, **kwargs)
    return wrapper


@app.after_request
def security_headers(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    if request.path.startswith('/api') or request.path in ('/admin', '/demo'):
        resp.headers['Cache-Control'] = 'no-store'
    return resp


def save_log(cur, row):
    sql = ("INSERT INTO logs (ip,ua,res,tz,lat,lng,city,score,platform,timestamp,status,reasons,verified,device,country,lang,simulated) "
           "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
    values = (row['ip'], row.get('ua', ''), row.get('res', ''), row['tz'], row['lat'], row['lng'], row['city'], row['score'],
              row['platform'], row['timestamp'], row['status'], json.dumps(row['reasons'], ensure_ascii=False),
              row.get('verified', 0), row.get('device', ''), row.get('country'), row.get('lang', ''), row.get('simulated', 0))
    if DATABASE_URL:
        cur.execute(q(sql) + ' RETURNING id', values)
        return cur.fetchone()[0]
    cur.execute(sql, values)
    return cur.lastrowid


def issue_reauth(cur, log_id, fp, place, now, simulated=False):
    token = secrets.token_urlsafe(24)
    expires = (now + timedelta(minutes=REAUTH_MINUTES)).isoformat()
    channels = otp_channels()
    otp_hash = None
    if channels and not simulated:
        code = f"{secrets.randbelow(1000000):06d}"
        otp_hash = sign(f'otp.{token}.{code}')
        send_otp(code, place)
    cur.execute(q("INSERT INTO reauth (token,log_id,fp,expires,otp_hash) VALUES (?,?,?,?,?)"), (token, log_id, fp, expires, otp_hash))
    return {'action': 'REAUTH', 'reauth_token': token, 'ttl': REAUTH_MINUTES * 60,
            'digits': 6 if otp_hash else 4, 'channel': '·'.join(channels) if otp_hash else ''}


_cleanup = {'t': 0}

def cleanup_old(force=False):
    if not force and time.time() - _cleanup['t'] < 3600:
        return 0
    _cleanup['t'] = time.time()
    now = now_kst()
    conn = get_conn(); cur = conn.cursor()
    cur.execute(q("DELETE FROM logs WHERE timestamp < ?"), (fmt_time(now - timedelta(days=RETENTION_DAYS)),))
    removed = cur.rowcount
    cur.execute(q("DELETE FROM reauth WHERE expires < ?"), ((now - timedelta(days=1)).isoformat(),))
    cur.execute(q("DELETE FROM reauth_fail WHERE ts < ?"), (fmt_time(now - timedelta(days=2)),))
    conn.commit(); conn.close()
    if removed:
        print(f'[보관 기간 만료] 기록 {removed}건 삭제')
    return removed


@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json(silent=True) or {}
    ip = client_ip()
    try:
        cleanup_old()
    except Exception as e:
        print(f'[정리 실패] {e}')
    plat = clip(data.get('plat') or 'Mobile', 40)
    browser_tz = clip(data.get('timezone'), 64)
    lang = clip(data.get('lang'), 35)
    rtc_ips = public_ips(data.get('rtc'))
    fp = fingerprint(data)
    cid = clip(data.get('cid'), 64)
    if not re.fullmatch(r'[A-Za-z0-9-]{8,64}', cid):
        cid = ''

    new_token = None
    did, saved_fp = read_device_token(str(data.get('device_token', '')))
    enroll_ok = False
    if data.get('enroll'):
        conn = get_conn(); cur = conn.cursor()
        if fail_count(cur, ['ip:' + ip]) < FAIL_LIMIT:
            enroll_ok = hmac.compare_digest(clip(data['enroll'], 128).encode(), ENROLL_KEY.encode())
            if not enroll_ok:
                add_fail(cur, ['ip:' + ip])
                conn.commit()
        conn.close()
    if enroll_ok:
        new_token = make_device_token(fp, did)
        device_state = 'KNOWN'
        device = did or new_token.split('.')[0]
    elif did is None:
        device_state = 'UNKNOWN'
        device = 'c-' + cid if cid else ''
    elif saved_fp == fp:
        device_state = 'KNOWN'
        device = did
    elif saved_fp == legacy_fingerprint(data):
        device_state = 'KNOWN'
        device = did
        new_token = make_device_token(fp, did)
    else:
        device_state = 'CHANGED'
        device = did

    now = now_kst()
    geo = lookup_ip(ip)
    print(f"[GeoIP] {ip} 브라우저={browser_tz} 언어={lang} WebRTC={rtc_ips} IP={geo}")

    leak_ip, leak_geo = check_webrtc(ip, rtc_ips)
    leak = None
    if leak_ip:
        where = ' '.join(x for x in ((leak_geo or {}).get('country'), (leak_geo or {}).get('city')) if x) or '위치 미상'
        leak = f"WebRTC로 확인된 실제 IP {leak_ip} ({where})"

    conn = get_conn(); cur = conn.cursor()
    keys = ['ip:' + ip, 'dev:' + device if device else '']
    blocked = manual_blocked(cur, keys)
    if not blocked and fail_count(cur, keys) >= FAIL_LIMIT:
        blocked = f'인증 실패 반복으로 {FAIL_WINDOW_HOURS}시간 자동 차단된 IP·기기'
    travel = check_travel(cur, device, geo, now)
    unusual = check_hour(cur, device, now)
    score, status, reasons = calc_score(browser_tz, geo, device_state, travel, blocked, check_lang(lang, geo), leak, unusual)
    vpn = any(r['code'] in ('TZ_MISMATCH', 'PROXY_IP', 'HOSTING_IP', 'WEBRTC_LEAK') for r in reasons)
    lat, lng, city = place_of(geo, vpn)

    log_id = save_log(cur, {'ip': ip, 'ua': clip(data.get('ua'), 300), 'res': clip(data.get('res'), 20), 'tz': browser_tz,
                            'lat': lat, 'lng': lng, 'city': city, 'score': score, 'platform': plat, 'timestamp': fmt_time(now),
                            'status': status, 'reasons': reasons, 'verified': -1 if blocked else 0, 'device': device,
                            'country': (geo or {}).get('countryCode'), 'lang': lang})

    resp = {"status": "success", "device_token": new_token, "action": "ALLOW"}
    if blocked:
        resp.update(action='BLOCKED', device_token=None)
    elif status == 'INTRUSION':
        resp.update(issue_reauth(cur, log_id, fp, city, now))

    conn.commit(); conn.close()
    if status == 'INTRUSION':
        notify(f"🚨 [Honey-Trap] {'차단된 접속' if blocked else '침입 의심'} {score}점\nIP {ip} · {city}\n{reasons_text(reasons)}")
    print(f"[저장] {ip} -> {city} {score}점 {status} {[r['code'] for r in reasons]}")
    return jsonify(resp)


@app.route('/reauth', methods=['POST'])
def reauth():
    data = request.get_json(silent=True) or {}
    token = clip(data.get('token'), 64)
    pin = clip(data.get('pin'), 8)
    ip = client_ip()

    conn = get_conn(); cur = conn.cursor()
    cur.execute(q("SELECT log_id, fp, expires, attempts, done, otp_hash FROM reauth WHERE token=?"), (token,))
    row = cur.fetchone()
    if row is None or row[4]:
        conn.close()
        return jsonify({'ok': False, 'locked': True, 'msg': '유효하지 않은 요청입니다.'}), 400
    log_id, fp, expires, attempts, _, otp_hash = row
    cur.execute(q(f"SELECT device FROM logs WHERE {id_col()}=?"), (log_id,))
    device = (cur.fetchone() or [''])[0] or ''
    keys = ['ip:' + ip, 'dev:' + device if device else '']

    if manual_blocked(cur, keys) or fail_count(cur, keys) >= FAIL_LIMIT:
        cur.execute(q(f"UPDATE logs SET verified=-1 WHERE {id_col()}=?"), (log_id,))
        conn.commit(); conn.close()
        return jsonify({'ok': False, 'locked': True, 'msg': '인증 실패가 반복되어 접근이 차단되었습니다.'}), 429
    if now_kst() > datetime.fromisoformat(expires):
        conn.close()
        return jsonify({'ok': False, 'locked': True, 'msg': '인증 시간이 만료되었습니다.'}), 410
    if attempts >= REAUTH_MAX_TRY:
        conn.close()
        return jsonify({'ok': False, 'locked': True, 'msg': '시도 횟수를 초과해 접근이 차단되었습니다.'}), 423

    if otp_hash:
        ok = hmac.compare_digest(sign(f'otp.{token}.{pin}'), otp_hash)
    else:
        ok = hmac.compare_digest(pin.encode(), REAUTH_PIN.encode())

    if ok:
        cur.execute(q("UPDATE reauth SET done=1 WHERE token=?"), (token,))
        cur.execute(q(f"UPDATE logs SET verified=1 WHERE {id_col()}=?"), (log_id,))
        conn.commit(); conn.close()
        did = device if device and not device.startswith('c-') else None
        return jsonify({'ok': True, 'device_token': make_device_token(fp, did)})

    attempts += 1
    cur.execute(q("UPDATE reauth SET attempts=? WHERE token=?"), (attempts, token))
    add_fail(cur, keys)
    left = REAUTH_MAX_TRY - attempts
    if left <= 0:
        cur.execute(q(f"UPDATE logs SET verified=-1 WHERE {id_col()}=?"), (log_id,))
    now_blocked = fail_count(cur, keys) >= FAIL_LIMIT
    conn.commit(); conn.close()
    if left <= 0:
        notify(f"⛔ [Honey-Trap] 재인증 3회 실패\nIP {ip}" + (f"\n실패 누적으로 {FAIL_WINDOW_HOURS}시간 자동 차단" if now_blocked else ''))
        return jsonify({'ok': False, 'locked': True, 'msg': '시도 횟수를 초과해 접근이 차단되었습니다.'}), 423
    return jsonify({'ok': False, 'locked': False, 'msg': f'인증 번호가 틀렸습니다. (남은 횟수 {left}회)'}), 401


def fetch_logs(cur, where='', params=(), limit=500):
    if DATABASE_URL:
        cur.execute(q(f"SELECT * FROM logs {where} ORDER BY id DESC LIMIT {int(limit)}"), params)
    else:
        cur.execute(f"SELECT rowid AS id, * FROM logs {where} ORDER BY rowid DESC LIMIT {int(limit)}", params)
    cols = [c[0] for c in cur.description]
    rows = [dict(zip(cols, r)) for r in cur.fetchall()]
    for r in rows:
        r.pop('ua', None)
        try:
            r['reasons'] = json.loads(r.get('reasons') or '[]')
        except ValueError:
            r['reasons'] = []
    return rows


@app.route('/api/logs')
@admin_required
def api_logs():
    try:
        after = max(int(request.args.get('after', 0)) - 50, 0)
    except ValueError:
        after = 0
    conn = get_conn(); cur = conn.cursor()
    rows = fetch_logs(cur, f"WHERE {id_col()} > ?", (after,))
    conn.close()
    return jsonify(rows)


@app.route('/api/stats')
@admin_required
def api_stats():
    try:
        days = min(max(int(request.args.get('days', 7)), 1), 31)
    except ValueError:
        days = 7
    today = now_kst().date()
    first = today - timedelta(days=days - 1)
    conn = get_conn(); cur = conn.cursor()
    rows = fetch_logs(cur, "WHERE timestamp >= ? AND (simulated=0 OR simulated IS NULL)", (first.strftime('%Y-%m-%d'),), limit=20000)
    blocks = list_blocks(cur)
    conn.close()

    daily = {(first + timedelta(days=i)).strftime('%Y-%m-%d'): {'SECURE': 0, 'SUSPICIOUS': 0, 'INTRUSION': 0} for i in range(days)}
    reason_count, country_count = Counter(), Counter()
    for r in rows:
        st = r.get('status') or ('SECURE' if r.get('score') == 0 else 'INTRUSION')
        day = (r.get('timestamp') or '')[:10]
        if day in daily:
            daily[day][st] = daily[day].get(st, 0) + 1
        for x in r['reasons']:
            reason_count[x['code']] += 1
        if r.get('country'):
            country_count[r['country']] += 1
    today_rows = [r for r in rows if (r.get('timestamp') or '').startswith(today.strftime('%Y-%m-%d'))]
    def summary(rs):
        return {'total': len(rs),
                'secure': sum(1 for r in rs if r.get('status') == 'SECURE'),
                'suspicious': sum(1 for r in rs if r.get('status') == 'SUSPICIOUS'),
                'intrusion': sum(1 for r in rs if r.get('status') == 'INTRUSION'),
                'passed': sum(1 for r in rs if r.get('verified') == 1),
                'blocked': sum(1 for r in rs if r.get('verified') == -1)}
    return jsonify({'today': summary(today_rows), 'period': summary(rows), 'days': days,
                    'daily': [{'date': d, **v} for d, v in daily.items()],
                    'top_reasons': [{'code': c, 'name': REASON_NAMES.get(c, c), 'count': n} for c, n in reason_count.most_common(6)],
                    'top_countries': [{'country': c, 'count': n} for c, n in country_count.most_common(6)],
                    'active_blocks': len(blocks)})


@app.route('/api/export.csv')
@admin_required
def api_export():
    conn = get_conn(); cur = conn.cursor()
    rows = fetch_logs(cur, limit=20000)
    conn.close()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(['번호', '시간', 'IP', '위치', '국가', '플랫폼', '브라우저 시간대', '언어', '점수', '판정', '재인증', '기기', '시뮬레이션', '감점 사유'])
    for r in reversed(rows):
        w.writerow([r['id'], r.get('timestamp'), r.get('ip'), r.get('city'), r.get('country') or '', r.get('platform'),
                    r.get('tz'), r.get('lang') or '', r.get('score'), r.get('status') or '',
                    {1: '통과', -1: '차단'}.get(r.get('verified'), ''), r.get('device') or '', 'Y' if r.get('simulated') else '',
                    ' / '.join(f"+{x['points']} {REASON_NAMES.get(x['code'], x['code'])}" for x in r['reasons'])])
    name = f"honeytrap_logs_{now_kst().strftime('%Y%m%d_%H%M')}.csv"
    return Response('﻿' + buf.getvalue(), mimetype='text/csv',
                    headers={'Content-Disposition': f'attachment; filename="{name}"'})


def list_blocks(cur):
    out = []
    cur.execute("SELECT block_key, reason, ts FROM manual_block ORDER BY ts DESC")
    for k, reason, ts in cur.fetchall():
        out.append({'key': k, 'type': 'manual', 'reason': reason, 'since': ts})
    since = fmt_time(now_kst() - timedelta(hours=FAIL_WINDOW_HOURS))
    cur.execute(q("SELECT fail_key, COUNT(*), MAX(ts) FROM reauth_fail WHERE ts > ? AND fail_key NOT LIKE ? GROUP BY fail_key"), (since, 'admin:%'))
    manual = {b['key'] for b in out}
    for k, n, ts in cur.fetchall():
        if n >= FAIL_LIMIT and k not in manual:
            out.append({'key': k, 'type': 'auto', 'reason': f'인증 실패 {n}회', 'since': ts})
    return out


@app.route('/api/blocks')
@admin_required
def api_blocks():
    conn = get_conn(); cur = conn.cursor()
    out = list_blocks(cur)
    conn.close()
    return jsonify(out)


def valid_block_key(key):
    return re.fullmatch(r'(ip|dev):[0-9A-Za-z.:\-]{1,70}', key or '') is not None


@app.route('/api/block', methods=['POST'])
@admin_required
@same_origin_required
def api_block():
    data = request.get_json(silent=True) or {}
    key = clip(data.get('key'), 80)
    if not valid_block_key(key):
        return jsonify({'error': '잘못된 대상입니다.'}), 400
    conn = get_conn(); cur = conn.cursor()
    cur.execute(q("INSERT INTO manual_block (block_key, reason, ts) VALUES (?,?,?) ON CONFLICT (block_key) DO NOTHING"),
                (key, '관리자가 직접 차단', fmt_time(now_kst())))
    conn.commit(); conn.close()
    notify(f"🔒 [Honey-Trap] 관리자가 {key} 차단")
    return jsonify({'ok': True})


@app.route('/api/unblock', methods=['POST'])
@admin_required
@same_origin_required
def api_unblock():
    data = request.get_json(silent=True) or {}
    key = clip(data.get('key'), 80)
    if not valid_block_key(key):
        return jsonify({'error': '잘못된 대상입니다.'}), 400
    conn = get_conn(); cur = conn.cursor()
    cur.execute(q("DELETE FROM manual_block WHERE block_key=?"), (key,))
    cur.execute(q("DELETE FROM reauth_fail WHERE fail_key=?"), (key,))
    conn.commit(); conn.close()
    return jsonify({'ok': True})


KR = {'country': 'South Korea', 'countryCode': 'KR', 'regionName': 'Jeollabuk-do', 'city': 'Jeonju', 'lat': 35.82, 'lon': 127.14,
      'timezone': 'Asia/Seoul', 'proxy': False, 'hosting': False}
SCENARIOS = {
    'normal': {'title': '정상 접속', 'desc': '등록한 기기로 집 와이파이에서 접속',
               'ip': '203.0.113.10', 'geo': KR, 'tz': 'Asia/Seoul', 'lang': 'ko-KR', 'device': 'KNOWN'},
    'vpn': {'title': '해외 VPN 우회', 'desc': '등록 기기에서 캐나다 VPN을 켜고 접속',
            'ip': '198.51.100.20', 'tz': 'Asia/Seoul', 'lang': 'ko-KR', 'device': 'KNOWN',
            'geo': {'country': 'Canada', 'countryCode': 'CA', 'regionName': 'Ontario', 'city': 'Toronto', 'lat': 43.70, 'lon': -79.40,
                    'timezone': 'America/Toronto', 'proxy': True, 'hosting': True}},
    'tz_spoof': {'title': '시간대까지 위조한 우회', 'desc': '기기 시간대를 미국으로 바꾸고 일반 회선으로 접속, 5분 전엔 전주에 있었음',
                 'ip': '198.51.100.30', 'tz': 'America/Los_Angeles', 'lang': 'ko-KR', 'device': 'KNOWN', 'travel': (35.82, 127.14, 5),
                 'geo': {'country': 'United States', 'countryCode': 'US', 'regionName': 'California', 'city': 'Los Angeles',
                         'lat': 34.05, 'lon': -118.24, 'timezone': 'America/Los_Angeles', 'proxy': False, 'hosting': False}},
    'token_theft': {'title': '기기 토큰 탈취', 'desc': '훔친 등록 토큰을 다른 기기의 브라우저에 넣고 국내에서 접속',
                    'ip': '203.0.113.40', 'geo': KR, 'tz': 'Asia/Seoul', 'lang': 'ko-KR', 'device': 'CHANGED'},
    'webrtc_leak': {'title': 'WebRTC로 실제 IP 유출', 'desc': '일본 VPN + 시간대 위조, 하지만 WebRTC가 한국 IP를 드러냄',
                    'ip': '198.51.100.50', 'tz': 'Asia/Tokyo', 'lang': 'ja-JP', 'device': 'UNKNOWN',
                    'leak': ('203.0.113.55', 'South Korea Jeonju'),
                    'geo': {'country': 'Japan', 'countryCode': 'JP', 'regionName': 'Tokyo', 'city': 'Tokyo', 'lat': 35.68, 'lon': 139.69,
                            'timezone': 'Asia/Tokyo', 'proxy': False, 'hosting': True}},
    'lang_mismatch': {'title': '언어·국가 불일치', 'desc': '한국어 브라우저로 미국 일반 회선에서 접속 (시간대도 미국으로 위조)',
                      'ip': '198.51.100.60', 'tz': 'America/New_York', 'lang': 'ko-KR', 'device': 'UNKNOWN',
                      'geo': {'country': 'United States', 'countryCode': 'US', 'regionName': 'New York', 'city': 'New York',
                              'lat': 40.71, 'lon': -74.01, 'timezone': 'America/New_York', 'proxy': False, 'hosting': False}},
    'unusual_hour': {'title': '평소와 다른 시간 접속', 'desc': '평소 낮에만 쓰던 등록 기기가 새벽 3시에 접속',
                     'ip': '203.0.113.70', 'geo': KR, 'tz': 'Asia/Seoul', 'lang': 'ko-KR', 'device': 'KNOWN', 'hour': 3},
    'brute_force': {'title': '인증 번호 대입 공격', 'desc': '재인증 번호를 6번 틀린 뒤 다시 접속',
                    'ip': '198.51.100.80', 'tz': 'Asia/Seoul', 'lang': 'ko-KR', 'device': 'UNKNOWN', 'blocked': True,
                    'geo': {'country': 'Canada', 'countryCode': 'CA', 'regionName': 'British Columbia', 'city': 'Vancouver',
                            'lat': 49.28, 'lon': -123.12, 'timezone': 'America/Vancouver', 'proxy': True, 'hosting': True}},
}


@app.route('/api/scenarios')
@admin_required
def api_scenarios():
    return jsonify([{'id': k, 'title': v['title'], 'desc': v['desc']} for k, v in SCENARIOS.items()])


@app.route('/api/simulate', methods=['POST'])
@admin_required
@same_origin_required
def api_simulate():
    data = request.get_json(silent=True) or {}
    sid = clip(data.get('scenario'), 30)
    sc = SCENARIOS.get(sid)
    if not sc:
        return jsonify({'error': '없는 시나리오입니다.'}), 400
    now = now_kst()
    geo = sc['geo']
    travel = None
    if sc.get('travel'):
        lat0, lng0, minutes = sc['travel']
        travel = travel_text(distance_km(lat0, lng0, geo['lat'], geo['lon']), minutes)
    leak = f"WebRTC로 확인된 실제 IP {sc['leak'][0]} ({sc['leak'][1]})" if sc.get('leak') else None
    unusual = f"평소 접속 시간대가 아닌 {sc['hour']}시에 접속 (최근 정상 접속 30건 기준)" if sc.get('hour') is not None else None
    blocked = f'인증 실패 반복으로 {FAIL_WINDOW_HOURS}시간 자동 차단된 IP·기기' if sc.get('blocked') else None
    score, status, reasons = calc_score(sc['tz'], geo, sc['device'], travel, blocked, check_lang(sc['lang'], geo), leak, unusual)
    vpn = any(r['code'] in ('TZ_MISMATCH', 'PROXY_IP', 'HOSTING_IP', 'WEBRTC_LEAK') for r in reasons)
    lat, lng, city = place_of(geo, vpn, use_vworld=False)

    conn = get_conn(); cur = conn.cursor()
    log_id = save_log(cur, {'ip': sc['ip'], 'tz': sc['tz'], 'lat': lat, 'lng': lng, 'city': '[시뮬레이션] ' + city, 'score': score,
                            'platform': 'Simulation', 'timestamp': fmt_time(now), 'status': status, 'reasons': reasons,
                            'verified': -1 if blocked else 0, 'device': 'sim-' + sid, 'country': geo.get('countryCode'),
                            'lang': sc['lang'], 'simulated': 1})
    action = 'BLOCKED' if blocked else ('REAUTH' if status == 'INTRUSION' else 'ALLOW')
    conn.commit(); conn.close()
    return jsonify({'id': log_id, 'scenario': sid, 'title': sc['title'], 'desc': sc['desc'], 'score': score, 'status': status,
                    'action': action, 'city': city, 'reasons': [{**r, 'name': REASON_NAMES.get(r['code'], r['code'])} for r in reasons]})


US = {'country': 'United States', 'countryCode': 'US', 'regionName': 'California', 'city': 'Los Angeles', 'lat': 34.05, 'lon': -118.24,
      'timezone': 'America/Los_Angeles', 'proxy': False, 'hosting': False}
JP = {'country': 'Japan', 'countryCode': 'JP', 'regionName': 'Tokyo', 'city': 'Tokyo', 'lat': 35.68, 'lon': 139.69,
      'timezone': 'Asia/Tokyo', 'proxy': False, 'hosting': False}
KR_VPN = {**KR, 'regionName': 'Seoul', 'city': 'Seoul', 'proxy': True, 'hosting': True}
BENCHMARK = [
    ('normal', '등록 기기 · 집 와이파이', dict(tz='Asia/Seoul', lang='ko-KR', geo=KR, device='KNOWN')),
    ('normal', '등록 기기 · LTE 접속', dict(tz='Asia/Seoul', lang='ko-KR', geo=KR, device='KNOWN')),
    ('normal', '처음 방문한 국내 사용자', dict(tz='Asia/Seoul', lang='ko-KR', geo=KR, device='UNKNOWN')),
    ('normal', '한국에 사는 외국인 (영어 브라우저)', dict(tz='Asia/Seoul', lang='en-US', geo=KR, device='UNKNOWN')),
    ('normal', '일본 여행 중 (폰 시간대 자동 변경)', dict(tz='Asia/Tokyo', lang='ko-KR', geo=JP, device='KNOWN')),
    ('normal', '미국 여행 중 (폰 시간대를 서울로 고정)', dict(tz='Asia/Seoul', lang='ko-KR', geo=US, device='KNOWN')),
    ('normal', '등록 기기 · 새벽 접속', dict(tz='Asia/Seoul', lang='ko-KR', geo=KR, device='KNOWN', unusual=True)),
    ('normal', '회사 VPN으로 재택근무 (등록 기기)', dict(tz='Asia/Seoul', lang='ko-KR', geo=KR_VPN, device='KNOWN')),
    ('attack', '해외 VPN 우회', dict(tz='Asia/Seoul', lang='ko-KR', geo=SCENARIOS['vpn']['geo'], device='KNOWN')),
    ('attack', '시간대까지 위조한 우회', dict(tz='America/Los_Angeles', lang='ko-KR', geo=US, device='KNOWN', travel=True)),
    ('attack', 'WebRTC로 실제 IP 유출', dict(tz='Asia/Tokyo', lang='ja-JP', geo={**JP, 'hosting': True}, device='UNKNOWN', leak=True)),
    ('attack', '인증 번호 대입 공격', dict(tz='Asia/Seoul', lang='ko-KR', geo=SCENARIOS['brute_force']['geo'], device='UNKNOWN', blocked=True)),
    ('attack', '국내 VPN 서버 · 미등록 기기', dict(tz='Asia/Seoul', lang='ko-KR', geo=KR_VPN, device='UNKNOWN')),
    ('attack', '국내 VPN 서버 · 탈취한 토큰', dict(tz='Asia/Seoul', lang='ko-KR', geo=KR_VPN, device='CHANGED')),
    ('attack', '기기 토큰 탈취 (국내)', dict(tz='Asia/Seoul', lang='ko-KR', geo=KR, device='CHANGED')),
    ('attack', '언어·국가 불일치 (시간대 위조)', dict(tz='America/New_York', lang='ko-KR', geo=SCENARIOS['lang_mismatch']['geo'], device='UNKNOWN')),
]


def benchmark_scores():
    out = []
    for label, name, c in BENCHMARK:
        travel = travel_text(distance_km(35.82, 127.14, c['geo']['lat'], c['geo']['lon']), 5) if c.get('travel') else None
        leak = 'WebRTC로 확인된 실제 IP (South Korea)' if c.get('leak') else None
        unusual = '평소 접속 시간대가 아닌 3시에 접속' if c.get('unusual') else None
        blocked = '인증 실패 반복으로 자동 차단' if c.get('blocked') else None
        score, _, reasons = calc_score(c['tz'], c['geo'], c['device'], travel, blocked, check_lang(c['lang'], c['geo']), leak, unusual, line=999)
        out.append({'label': label, 'name': name, 'score': score, 'reasons': [REASON_NAMES.get(r['code'], r['code']) for r in reasons]})
    return out


@app.route('/api/tuning')
@admin_required
def api_tuning():
    cases = benchmark_scores()
    attacks = [c for c in cases if c['label'] == 'attack']
    normals = [c for c in cases if c['label'] == 'normal']
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT score FROM logs WHERE simulated=0 OR simulated IS NULL")
    real = [r[0] or 0 for r in cur.fetchall()]
    conn.close()
    rows = []
    for t in range(40, 95, 5):
        tp = sum(1 for c in attacks if c['score'] >= t)
        fp = sum(1 for c in normals if c['score'] >= t)
        rows.append({'line': t, 'detected': tp, 'attacks': len(attacks), 'false_alarms': fp, 'normals': len(normals),
                     'real_reauth': sum(1 for x in real if x >= t), 'real_total': len(real)})
    return jsonify({'current': reauth_line(), 'rows': rows, 'cases': cases})


@app.route('/api/settings', methods=['GET'])
@admin_required
def api_settings_get():
    return jsonify({'reauth_line': reauth_line(), 'suspicious_line': SUSPICIOUS_LINE, 'retention_days': RETENTION_DAYS,
                    'geolite': _geolite['status'], 'otp': otp_channels()})


@app.route('/api/settings', methods=['POST'])
@admin_required
@same_origin_required
def api_settings_set():
    data = request.get_json(silent=True) or {}
    try:
        line = int(data.get('reauth_line'))
    except (TypeError, ValueError):
        return jsonify({'error': '숫자를 입력하세요.'}), 400
    if not 40 <= line <= 95:
        return jsonify({'error': '재인증 기준은 40~95점 사이여야 합니다.'}), 400
    conn = get_conn(); cur = conn.cursor()
    cur.execute(q("DELETE FROM settings WHERE skey=?"), ('reauth_line',))
    cur.execute(q("INSERT INTO settings (skey, value) VALUES (?,?)"), ('reauth_line', str(line)))
    conn.commit(); conn.close()
    _setting_cache['t'] = 0
    notify(f"⚙️ [Honey-Trap] 재인증 기준이 {line}점으로 변경됨")
    return jsonify({'ok': True, 'reauth_line': reauth_line()})


@app.route('/api/clear', methods=['POST'])
@admin_required
@same_origin_required
def api_clear():
    conn = get_conn(); cur = conn.cursor()
    cur.execute("DELETE FROM logs")
    cur.execute("DELETE FROM reauth")
    cur.execute("DELETE FROM reauth_fail")
    conn.commit(); conn.close()
    return jsonify({"status": "cleared"})

@app.route('/admin')
@admin_required
def admin(): return send_from_directory(BASE_DIR, 'dashboard.html')

@app.route('/demo')
@admin_required
def demo(): return send_from_directory(BASE_DIR, 'demo.html')

@app.route('/')
def index(): return send_from_directory(BASE_DIR, 'index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 8080)))
