import sqlite3, os, requests, math
from flask import Flask, request, jsonify, send_from_directory
from flask_socketio import SocketIO
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'security.db')

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")
VWORLD_KEY = "1B733389-A039-49D0-83F3-6ACD3F8082A2"
last_loc = {'lat': None, 'lng': None}

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''CREATE TABLE IF NOT EXISTS logs
                    (ip TEXT, ua TEXT, res TEXT, tz TEXT, lat REAL, lng REAL, city TEXT, score INTEGER, platform TEXT, timestamp TEXT)''')
    conn.commit(); conn.close()
    print(f"[DB OK] {DB_PATH}")
init_db()

def get_detail_address(lng, lat):
    try:
        url = f"https://api.vworld.kr/req/address?service=address&request=getAddress&version=2.0&crs=epsg:4326&point={lng},{lat}&format=json&type=both&key={VWORLD_KEY}"
        r = requests.get(url, timeout=3).json()
        if r.get('response',{}).get('result'):
            return r['response']['result'][0].get('text')
    except: pass
    return f"{lat},{lng}"

@socketio.on('client_location')
def handle_client_location(data):
    global last_loc
    lng, lat = data.get('lng'), data.get('lat')
    if not lng or not lat: return
    if last_loc['lat']:
        R=6371000
        dlat=math.radians(lat-last_loc['lat']); dlng=math.radians(lng-last_loc['lng'])
        a=math.sin(dlat/2)**2 + math.cos(math.radians(last_loc['lat']))*math.cos(math.radians(lat))*math.sin(dlng/2)**2
        if R*2*math.asin(math.sqrt(a)) < 10: return
    last_loc={'lat':lat,'lng':lng}
    ip=request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0]
    city=get_detail_address(lng,lat)
    now=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn=sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO logs VALUES (?,?,?,?,?,?,?,?,?,?)",(ip,'','','Asia/Seoul',lat,lng,city,0,'iPhone GPS',now))
    conn.commit(); conn.close()
    print(f"[저장됨] {city}")
    socketio.emit('new_log',{'ip':ip,'platform':'iPhone GPS','city':city,'lat':lat,'lng':lng,'timestamp':now,'score':0,'is_tempered':False,'tz':'Asia/Seoul'})

@app.route('/scan', methods=['POST'])
def scan():
    data=request.json or {}
    ip=request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0]
    plat=data.get('plat','Mobile')
    lng,lat=data.get('lng'),data.get('lat')
    city=get_detail_address(lng,lat) if lng and lat else "IP 위치"
    if not lat: lat,lng=35.8242,127.1480
    now=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn=sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO logs VALUES (?,?,?,?,?,?,?,?,?,?)",(ip,data.get('ua',''),data.get('res',''),'Asia/Seoul',lat,lng,city,0,plat,now))
    conn.commit(); conn.close()
    print(f"[저장됨] {ip} -> {city}")
    socketio.emit('new_log',{'ip':ip,'platform':plat,'city':city,'lat':lat,'lng':lng,'timestamp':now,'score':0,'is_tempered':False,'tz':'Asia/Seoul'})
    return jsonify({"status":"success"})

@app.route('/api/logs')
def api_logs():
    conn=sqlite3.connect(DB_PATH); conn.row_factory=sqlite3.Row
    rows=conn.execute("SELECT * FROM logs ORDER BY rowid DESC LIMIT 500").fetchall(); conn.close()
    print(f"[API] {len(rows)}개 반환")
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
    socketio.run(app, host='0.0.0.0', port=8080, allow_unsafe_werkzeug=True)