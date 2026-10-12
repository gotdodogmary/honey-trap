import sqlite3, os, requests, hmac, hashlib, secrets, json
from flask import Flask, request, jsonify, send_from_directory
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'security.db')
app = Flask(__name__)
KST = ZoneInfo('Asia/Seoul')
VWORLD_KEY = "1B733389-A039-49D0-83F3-6ACD3F8082A2"
SECRET_KEY = os.environ.get('SECRET_KEY', 'change-me-in-render')
ENROLL_KEY = os.environ.get('ENROLL_KEY', 'mary_safe_key')
REAUTH_PIN = os.environ.get('REAUTH_PIN', '1234')
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL:
    import psycopg2

WEIGHTS = {
    'TZ_MISMATCH': 60,
    'PROXY_IP': 20,
    'HOSTING_IP': 15,
    'UNKNOWN_DEVICE': 30,
    'FP_CHANGED': 40,
}
SUSPICIOUS_LINE = 30
REAUTH_LINE = 60
REAUTH_MINUTES = 5
REAUTH_MAX_TRY = 3


def get_conn():
    if DATABASE_URL:
        return psycopg2.connect(DATABASE_URL)
    return sqlite3.connect(DB_PATH)

def q(sql):
    return sql.replace('?', '%s') if DATABASE_URL else sql

def now_kst():
    return datetime.now(KST)


def sign(text):
    return hmac.new(SECRET_KEY.encode(), text.encode(), hashlib.sha256).hexdigest()[:32]

def make_device_token(fp):
    did = secrets.token_hex(8)
    return f"{did}.{fp}.{sign(did + '.' + fp)}"

def read_device_token(token):
    try:
        did, fp, sig = token.split('.')
        if hmac.compare_digest(sig, sign(did + '.' + fp)):
            return fp
    except Exception:
        pass
    return None

def fingerprint(data):
    raw = '|'.join(str(data.get(k, '')) for k in ('ua', 'res', 'plat', 'fp'))
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def lookup_ip(ip):
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,lat,lon,timezone,proxy,hosting"
        j = requests.get(url, timeout=4).json()
        if j.get('status') == 'success':
            return j
        print(f"[ip-api FAIL] {j}")
    except Exception as e:
        print(f"[ip-api FAIL] {e}")

    try:
        j = requests.get(f"https://ipwho.is/{ip}", timeout=4).json()
        if j.get('success'):
            sec = j.get('security') or {}
            return {'country': j.get('country'), 'regionName': j.get('region'), 'city': j.get('city'),
                    'lat': j.get('latitude'), 'lon': j.get('longitude'),
                    'timezone': (j.get('timezone') or {}).get('id'),
                    'proxy': bool(sec.get('vpn') or sec.get('proxy')), 'hosting': bool(sec.get('hosting'))}
        print(f"[ipwho FAIL] {j}")
    except Exception as e:
        print(f"[ipwho FAIL] {e}")
    return None


def calc_score(browser_tz, geo, device_state):
    reasons = []
    if geo:
        if geo.get('timezone') and geo.get('timezone') != browser_tz:
            reasons.append(('TZ_MISMATCH', f"브라우저 {browser_tz} / IP {geo.get('timezone')}"))
        if geo.get('proxy'):
            reasons.append(('PROXY_IP', '프록시/VPN 대역 IP'))
        if geo.get('hosting'):
            reasons.append(('HOSTING_IP', '데이터센터 IP'))
    if device_state == 'UNKNOWN':
        reasons.append(('UNKNOWN_DEVICE', '등록되지 않은 기기'))
    elif device_state == 'CHANGED':
        reasons.append(('FP_CHANGED', '등록 기기의 지문 값이 달라짐'))

    reasons = [{'code': c, 'points': WEIGHTS[c], 'detail': d} for c, d in reasons]
    score = min(100, sum(r['points'] for r in reasons))
    if score >= REAUTH_LINE:
        status = 'INTRUSION'
    elif score >= SUSPICIOUS_LINE:
        status = 'SUSPICIOUS'
    else:
        status = 'SECURE'
    return score, status, reasons


def init_db():
    conn = get_conn(); cur = conn.cursor()
    if DATABASE_URL:
        cur.execute('''CREATE TABLE IF NOT EXISTS logs
                       (id SERIAL PRIMARY KEY, ip TEXT, ua TEXT, res TEXT, tz TEXT, lat DOUBLE PRECISION, lng DOUBLE PRECISION,
                        city TEXT, score INTEGER, platform TEXT, timestamp TEXT)''')
        for col, typ in (('status', 'TEXT'), ('reasons', 'TEXT'), ('verified', 'INTEGER DEFAULT 0')):
            cur.execute(f'ALTER TABLE logs ADD COLUMN IF NOT EXISTS {col} {typ}')
    else:
        cur.execute('''CREATE TABLE IF NOT EXISTS logs
                       (ip TEXT, ua TEXT, res TEXT, tz TEXT, lat REAL, lng REAL, city TEXT, score INTEGER, platform TEXT, timestamp TEXT)''')
        have = [r[1] for r in cur.execute('PRAGMA table_info(logs)').fetchall()]
        for col, typ in (('status', 'TEXT'), ('reasons', 'TEXT'), ('verified', 'INTEGER DEFAULT 0')):
            if col not in have:
                cur.execute(f'ALTER TABLE logs ADD COLUMN {col} {typ}')
    cur.execute('''CREATE TABLE IF NOT EXISTS reauth
                   (token TEXT PRIMARY KEY, log_id INTEGER, fp TEXT, expires TEXT,
                    attempts INTEGER DEFAULT 0, done INTEGER DEFAULT 0)''')
    conn.commit(); conn.close()
init_db()


def get_detail_address(lng, lat):
    try:
        url = f"https://api.vworld.kr/req/address?service=address&request=getAddress&version=2.0&crs=epsg:4326&point={lng},{lat}&format=json&type=both&key={VWORLD_KEY}"
        r = requests.get(url, timeout=4).json()
        result = r.get('response',{}).get('result',[])
        if result and result[0].get('text'):
            txt = result[0]['text']
            print(f"[VWorld OK] {txt}")
            return txt
    except Exception as e:
        print(f"[VWorld FAIL] {e}")

    try:
        url = f"https://api.bigdatacloud.net/data/reverse-geocode-client?latitude={lat}&longitude={lng}&localityLanguage=ko"
        j = requests.get(url, timeout=5).json()
        city = j.get('city') or j.get('locality') or ''
        gu = j.get('principalSubdivision') or ''
        country = j.get('countryName') or ''
        if city:
            full = f"{country} {gu} {city}"
            print(f"[BigDataCloud OK] {full}")
            return full
    except Exception as e:
        print(f"[BigDataCloud FAIL] {e}")

    try:
        url = f"https://nominatim.openstreetmap.org/reverse?format=json&lat={lat}&lon={lng}&zoom=18&accept-language=ko"
        j = requests.get(url, headers={"User-Agent":"honey-trap/1.0 (admin@honey-trap.com)"}, timeout=5).json()
        if j.get('display_name'):
            addr = j['display_name'].replace('대한민국, ','')
            print(f"[OSM OK] {addr}")
            return addr
    except Exception as e:
        print(f"[OSM FAIL] {e}")

    print("[ALL FAIL] 좌표 반환")
    return f"{lat:.6f}, {lng:.6f}"


@app.route('/scan', methods=['POST'])
def scan():
    data=request.json or {}
    ip=request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    plat=data.get('plat','Mobile')
    lng,lat=data.get('lng'),data.get('lat')
    fp = fingerprint(data)

    new_token = None
    if data.get('enroll') and hmac.compare_digest(str(data['enroll']), ENROLL_KEY):
        new_token = make_device_token(fp)
        device_state = 'KNOWN'
    else:
        saved_fp = read_device_token(str(data.get('device_token', '')))
        if saved_fp is None:
            device_state = 'UNKNOWN'
        elif saved_fp == fp:
            device_state = 'KNOWN'
        else:
            device_state = 'CHANGED'

    geo = lookup_ip(ip)
    browser_tz = data.get('timezone', '')
    print(f"[GeoIP] {ip} 브라우저={browser_tz} IP={geo}")
    score, status, reasons = calc_score(browser_tz, geo, device_state)
    vpn = any(r['code'] in ('TZ_MISMATCH', 'PROXY_IP', 'HOSTING_IP') for r in reasons)

    if vpn and geo:
        lat, lng = geo['lat'], geo['lon']
        city = f"{geo.get('country','')} {geo.get('regionName','')} {geo.get('city','')} (VPN 의심: {geo.get('timezone')})"
    elif lat and lng:
        try:
            lat=float(lat); lng=float(lng)
            city=get_detail_address(lng,lat)
        except Exception as e:
            print(f"좌표 파싱 실패: {e}")
            lat,lng=35.8242,127.1480
            city="IP 위치 (GPS 거부)"
    elif geo:
        lat, lng = geo['lat'], geo['lon']
        city = f"{geo.get('country','')} {geo.get('regionName','')} {geo.get('city','')}"
    else:
        lat,lng=35.8242,127.1480
        city="IP 위치 (GPS 거부)"

    now=now_kst().strftime('%Y-%m-%d %H:%M:%S')
    conn=get_conn(); cur=conn.cursor()
    sql = "INSERT INTO logs (ip,ua,res,tz,lat,lng,city,score,platform,timestamp,status,reasons,verified) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,0)"
    values = (ip,data.get('ua',''),data.get('res',''),browser_tz,lat,lng,city,score,plat,now,status,json.dumps(reasons, ensure_ascii=False))
    if DATABASE_URL:
        cur.execute(q(sql) + ' RETURNING id', values)
        log_id = cur.fetchone()[0]
    else:
        cur.execute(sql, values)
        log_id = cur.lastrowid

    resp = {"status":"success","address":city,"device_token":new_token,"action":"ALLOW"}
    if status == 'INTRUSION':
        token = secrets.token_urlsafe(24)
        expires = (now_kst() + timedelta(minutes=REAUTH_MINUTES)).isoformat()
        cur.execute(q("INSERT INTO reauth (token,log_id,fp,expires) VALUES (?,?,?,?)"), (token, log_id, fp, expires))
        resp.update(action='REAUTH', reauth_token=token, ttl=REAUTH_MINUTES*60)

    conn.commit(); conn.close()
    print(f"[저장] {ip} -> {city} {score}점 {status} {[r['code'] for r in reasons]}")
    return jsonify(resp)


@app.route('/reauth', methods=['POST'])
def reauth():
    data = request.json or {}
    token = str(data.get('token', ''))
    pin = str(data.get('pin', ''))

    conn = get_conn(); cur = conn.cursor()
    cur.execute(q("SELECT log_id, fp, expires, attempts, done FROM reauth WHERE token=?"), (token,))
    row = cur.fetchone()
    if row is None or row[4]:
        conn.close()
        return jsonify({'ok': False, 'locked': True, 'msg': '유효하지 않은 요청입니다.'}), 400
    log_id, fp, expires, attempts, _ = row

    if now_kst() > datetime.fromisoformat(expires):
        conn.close()
        return jsonify({'ok': False, 'locked': True, 'msg': '인증 시간이 만료되었습니다.'}), 410
    if attempts >= REAUTH_MAX_TRY:
        conn.close()
        return jsonify({'ok': False, 'locked': True, 'msg': '시도 횟수를 초과해 접근이 차단되었습니다.'}), 423

    if hmac.compare_digest(pin.encode(), REAUTH_PIN.encode()):
        cur.execute(q("UPDATE reauth SET done=1 WHERE token=?"), (token,))
        cur.execute(q("UPDATE logs SET verified=1 WHERE " + ("id" if DATABASE_URL else "rowid") + "=?"), (log_id,))
        conn.commit(); conn.close()
        return jsonify({'ok': True, 'device_token': make_device_token(fp)})

    attempts += 1
    cur.execute(q("UPDATE reauth SET attempts=? WHERE token=?"), (attempts, token))
    left = REAUTH_MAX_TRY - attempts
    if left <= 0:
        cur.execute(q("UPDATE logs SET verified=-1 WHERE " + ("id" if DATABASE_URL else "rowid") + "=?"), (log_id,))
    conn.commit(); conn.close()
    if left <= 0:
        return jsonify({'ok': False, 'locked': True, 'msg': '시도 횟수를 초과해 접근이 차단되었습니다.'}), 423
    return jsonify({'ok': False, 'locked': False, 'msg': f'인증 번호가 틀렸습니다. (남은 횟수 {left}회)'}), 401


@app.route('/api/logs')
def api_logs():
    conn=get_conn(); cur=conn.cursor()
    if DATABASE_URL:
        cur.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 500")
    else:
        cur.execute("SELECT rowid AS id, * FROM logs ORDER BY rowid DESC LIMIT 500")
    cols=[c[0] for c in cur.description]
    rows=[dict(zip(cols,r)) for r in cur.fetchall()]
    conn.close()
    for r in rows:
        try:
            r['reasons'] = json.loads(r.get('reasons') or '[]')
        except ValueError:
            r['reasons'] = []
    return jsonify(rows)

@app.route('/api/clear', methods=['POST'])
def api_clear():
    conn=get_conn(); cur=conn.cursor()
    cur.execute("DELETE FROM logs")
    cur.execute("DELETE FROM reauth")
    conn.commit(); conn.close()
    return jsonify({"status":"cleared"})

@app.route('/admin')
def admin(): return send_from_directory(BASE_DIR, 'dashboard.html')
@app.route('/')
def index(): return send_from_directory(BASE_DIR, 'index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT",8080)))
