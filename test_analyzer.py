import os
import re
import sys
import json
import base64
import tempfile
import unittest
from datetime import timedelta

TMP = tempfile.mkdtemp()
os.environ.update(
    SQLITE_PATH=os.path.join(TMP, 'test.db'),
    SECRET_KEY='test-secret',
    ENROLL_KEY='test-enroll',
    REAUTH_PIN='4821',
    ADMIN_PASSWORD='test-admin',
    GEOLITE2_PATH=os.path.join(TMP, 'none.mmdb'),
)
os.environ.pop('DATABASE_URL', None)
for k in ('TELEGRAM_BOT_TOKEN', 'TELEGRAM_CHAT_ID', 'DISCORD_WEBHOOK_URL', 'BREVO_API_KEY', 'OTP_EMAIL',
          'MAXMIND_ACCOUNT_ID', 'MAXMIND_LICENSE_KEY'):
    os.environ.pop(k, None)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import analyzer as a

GEO = {
    '211.214.20.58': {'country': 'South Korea', 'countryCode': 'KR', 'regionName': 'Jeonbuk', 'city': 'Jeonju',
                      'lat': 35.82, 'lon': 127.14, 'timezone': 'Asia/Seoul', 'proxy': False, 'hosting': False},
    '121.154.59.135': {'country': 'South Korea', 'countryCode': 'KR', 'regionName': 'Seoul', 'city': 'Seoul',
                       'lat': 37.56, 'lon': 126.97, 'timezone': 'Asia/Seoul', 'proxy': False, 'hosting': False},
    '149.88.98.165': {'country': 'Canada', 'countryCode': 'CA', 'regionName': 'Ontario', 'city': 'Toronto',
                      'lat': 43.70, 'lon': -79.40, 'timezone': 'America/Toronto', 'proxy': True, 'hosting': True},
    '149.88.98.170': {'country': 'Canada', 'countryCode': 'CA', 'regionName': 'Ontario', 'city': 'Toronto',
                      'lat': 43.70, 'lon': -79.40, 'timezone': 'America/Toronto', 'proxy': False, 'hosting': True},
    '8.8.4.4': {'country': 'United States', 'countryCode': 'US', 'regionName': 'California', 'city': 'Los Angeles',
                'lat': 34.05, 'lon': -118.24, 'timezone': 'America/Los_Angeles', 'proxy': False, 'hosting': False},
}
REAL_LOOKUP = a.lookup_ip
a.lookup_ip = lambda ip: GEO.get(ip)
SENT = []
a._send = lambda url, **kw: SENT.append(kw.get('json') or {})
a.get_detail_address = lambda lng, lat: None

ADMIN = {'Authorization': 'Basic ' + base64.b64encode(b'admin:test-admin').decode()}
SAME = {'X-Requested-With': 'honey-trap'}
BODY = {'ua': 'Mozilla/5.0 Chrome/130.0', 'res': '1440x900', 'plat': 'MacIntel', 'fp': 'abc',
        'timezone': 'Asia/Seoul', 'lang': 'ko-KR'}


def body(**kw):
    d = dict(BODY)
    d.update(kw)
    return d


class Base(unittest.TestCase):
    def setUp(self):
        self.c = a.app.test_client()
        a._setting_cache['t'] = 0
        a.TELEGRAM_BOT_TOKEN = a.TELEGRAM_CHAT_ID = ''

    def scan(self, ip, **kw):
        return self.c.post('/scan', json=body(**kw), headers={'CF-Connecting-IP': ip}).get_json()

    def enroll(self, ip='211.214.20.58', **kw):
        r = self.scan(ip, enroll='test-enroll', **kw)
        self.assertTrue(r['device_token'])
        return r['device_token']

    def last_log(self):
        return self.c.get('/api/logs', headers=ADMIN).get_json()[0]


class ScoringTest(Base):
    def test_normal_registered_is_secure(self):
        score, status, reasons = a.calc_score('Asia/Seoul', GEO['211.214.20.58'], 'KNOWN', line=60)
        self.assertEqual((score, status, reasons), (0, 'SECURE', []))

    def test_vpn_timezone_mismatch_is_intrusion(self):
        score, status, reasons = a.calc_score('Asia/Seoul', GEO['149.88.98.165'], 'KNOWN', line=60)
        self.assertEqual(status, 'INTRUSION')
        self.assertIn('TZ_MISMATCH', [r['code'] for r in reasons])
        self.assertEqual(score, 95)

    def test_same_country_timezone_is_not_mismatch(self):
        geo = dict(GEO['8.8.4.4'], timezone='America/New_York')
        _, _, reasons = a.calc_score('America/Los_Angeles', geo, 'KNOWN', line=60)
        self.assertNotIn('TZ_MISMATCH', [r['code'] for r in reasons])

    def test_threshold_boundary(self):
        self.assertEqual(a.calc_score('Asia/Seoul', GEO['211.214.20.58'], 'UNKNOWN', line=60)[1], 'SUSPICIOUS')
        self.assertEqual(a.calc_score('Asia/Seoul', GEO['211.214.20.58'], 'UNKNOWN', line=30)[1], 'INTRUSION')

    def test_language_country(self):
        self.assertIsNotNone(a.check_lang('ko-KR', {'countryCode': 'US'}))
        self.assertIsNone(a.check_lang('ko-KR', {'countryCode': 'KR'}))
        self.assertIsNone(a.check_lang('ko', {'countryCode': 'KR'}))
        self.assertIsNone(a.check_lang('en', {'countryCode': 'KR'}))

    def test_impossible_travel(self):
        self.assertIsNotNone(a.travel_text(9700, 5))
        self.assertIsNone(a.travel_text(190, 5))
        self.assertIsNone(a.travel_text(9700, 60 * 13))

    def test_webrtc_leak_same_family_only(self):
        self.assertEqual(a.check_webrtc('149.88.98.165', ['211.214.20.58'])[0], '211.214.20.58')
        self.assertIsNone(a.check_webrtc('149.88.98.165', ['2001:4860:4860::8888'])[0])
        self.assertIsNone(a.check_webrtc('149.88.98.165', ['149.88.98.165'])[0])

    def test_public_ip_filter(self):
        self.assertEqual(a.public_ips(['10.0.0.1', '8.8.8.8', 'abc', '192.168.0.1']), ['8.8.8.8'])


class FlowTest(Base):
    def test_registered_device_secure_on_other_network(self):
        token = self.enroll()
        self.assertEqual(self.scan('121.154.59.135', device_token=token)['action'], 'ALLOW')
        self.assertEqual(self.last_log()['status'], 'SECURE')

    def test_browser_update_keeps_device(self):
        token = self.enroll(ua='Mozilla/5.0 Chrome/130.0.1')
        self.scan('211.214.20.58', device_token=token, ua='Mozilla/5.0 Chrome/131.0.9')
        self.assertEqual(self.last_log()['score'], 0)

    def test_vpn_requires_reauth_and_fixed_pin(self):
        token = self.enroll()
        r = self.scan('149.88.98.165', device_token=token)
        self.assertEqual((r['action'], r['digits']), ('REAUTH', 4))
        ok = self.c.post('/reauth', json={'token': r['reauth_token'], 'pin': '4821'},
                         headers={'CF-Connecting-IP': '149.88.98.165'}).get_json()
        self.assertTrue(ok['ok'])

    def test_otp_sent_by_telegram(self):
        a.TELEGRAM_BOT_TOKEN, a.TELEGRAM_CHAT_ID = 'T', 'C'
        SENT.clear()
        r = self.scan('149.88.98.165', cid='cid-otp-test-01')
        self.assertEqual(r['digits'], 6)
        import time
        for _ in range(50):
            codes = [re.search(r'번호 (\d{6})', m.get('text', '')) for m in SENT]
            codes = [m.group(1) for m in codes if m]
            if codes:
                break
            time.sleep(0.05)
        self.assertTrue(codes)
        wrong = self.c.post('/reauth', json={'token': r['reauth_token'], 'pin': '4821'},
                            headers={'CF-Connecting-IP': '149.88.98.165'}).get_json()
        self.assertFalse(wrong['ok'])
        ok = self.c.post('/reauth', json={'token': r['reauth_token'], 'pin': codes[0]},
                         headers={'CF-Connecting-IP': '149.88.98.165'}).get_json()
        self.assertTrue(ok['ok'])

    def test_bruteforce_is_blocked_after_six_failures(self):
        ip = '8.8.4.4'
        for _ in range(2):
            r = self.scan(ip, cid='cid-brute-0001')
            for pin in ('0000', '1111', '2222'):
                self.c.post('/reauth', json={'token': r['reauth_token'], 'pin': pin}, headers={'CF-Connecting-IP': ip})
        self.assertEqual(self.scan(ip, cid='cid-brute-0001')['action'], 'BLOCKED')
        keys = [b['key'] for b in self.c.get('/api/blocks', headers=ADMIN).get_json()]
        self.assertIn('ip:' + ip, keys)
        self.assertTrue(any(k.startswith('dev:') for k in keys))
        for k in keys:
            self.c.post('/api/unblock', json={'key': k}, headers={**ADMIN, **SAME})
        self.assertNotEqual(self.scan(ip, cid='cid-brute-0001')['action'], 'BLOCKED')

    def test_forwarded_for_header_is_ignored(self):
        r = self.c.post('/scan', json=body(), headers={'CF-Connecting-IP': '149.88.98.165', 'X-Forwarded-For': '211.214.20.58'}).get_json()
        self.assertEqual(r['action'], 'REAUTH')

    def test_wrong_enroll_key(self):
        r = self.scan('121.154.59.135', enroll='nope')
        self.assertIsNone(r['device_token'])

    def test_webrtc_leak_gives_real_city(self):
        SENT.clear()
        a.TELEGRAM_BOT_TOKEN, a.TELEGRAM_CHAT_ID = 'T', 'C'
        self.scan('149.88.98.165', cid='cid-real-webrtc1', rtc=['211.214.20.58'])
        log = self.last_log()
        self.assertEqual((log['real_src'], log['real_city']), ('webrtc', 'Jeonju, South Korea'))
        self.assertAlmostEqual(log['real_lat'], 35.82)
        self.assertTrue(any('추정 실제 위치: Jeonju' in m.get('text', '') for m in SENT))

    def test_other_vpn_server_ip_is_not_a_leak(self):
        self.assertIsNone(a.check_webrtc('149.88.98.165', ['149.88.98.170'], GEO['149.88.98.165'])[0])
        token = self.enroll()
        self.scan('149.88.98.165', device_token=token, rtc=['149.88.98.170'])
        log = self.last_log()
        self.assertNotIn('WEBRTC_LEAK', [r['code'] for r in log['reasons']])
        self.assertEqual(log['real_src'], 'last')
        self.assertIn('Jeonju', log['real_city'])

    def test_registered_device_vpn_gives_last_city(self):
        token = self.enroll()
        self.scan('149.88.98.165', device_token=token)
        log = self.last_log()
        self.assertEqual(log['real_src'], 'last')
        self.assertIn('Jeonju', log['real_city'])

    def test_normal_access_has_no_real_city(self):
        token = self.enroll()
        self.scan('121.154.59.135', device_token=token)
        self.assertIsNone(self.last_log()['real_city'])


class GpsTest(Base):
    GPS = {'lat': 35.8467, 'lng': 127.1294, 'acc': 20}

    def test_gps_pins_registered_device(self):
        token = self.enroll(gps=self.GPS)
        self.assertAlmostEqual(self.last_log()['lat'], 35.8467)
        self.scan('121.154.59.135', device_token=token, gps=self.GPS)
        log = self.last_log()
        self.assertEqual((log['lat'], log['lng'], log['status']), (35.8467, 127.1294, 'SECURE'))
        self.assertTrue(log['city'].startswith('GPS 35.847'))
        self.assertIsNone(log['real_city'])

    def test_gps_is_real_location_behind_vpn(self):
        a.TELEGRAM_BOT_TOKEN, a.TELEGRAM_CHAT_ID = 'T', 'C'
        SENT.clear()
        token = self.enroll(gps=self.GPS)
        self.scan('149.88.98.165', device_token=token, gps=self.GPS)
        log = self.last_log()
        self.assertIn('Toronto', log['city'])
        self.assertEqual((log['real_src'], log['real_lat'], log['real_lng']), ('gps', 35.8467, 127.1294))
        import time
        for _ in range(40):
            if any('실제 위치(GPS)' in m.get('text', '') for m in SENT):
                break
            time.sleep(0.05)
        self.assertTrue(any('실제 위치(GPS)' in m.get('text', '') for m in SENT))

    def test_gps_from_unknown_device_is_ignored(self):
        self.scan('121.154.59.135', cid='cid-gps-unknown1', gps=self.GPS)
        self.assertAlmostEqual(self.last_log()['lat'], 37.56)
        self.scan('149.88.98.165', cid='cid-gps-unknown1', gps=self.GPS)
        self.assertNotEqual(self.last_log()['real_src'], 'gps')

    def test_bad_gps_values(self):
        for v in (None, 'x', {'lat': 'a', 'lng': 1}, {'lat': 200, 'lng': 1}, {'lat': 0, 'lng': 0}, {'lat': 35, 'lng': 127, 'acc': 9999}):
            self.assertIsNone(a.read_gps(v))
        self.assertEqual(a.read_gps(self.GPS), (35.8467, 127.1294, 20))


class LookupTest(unittest.TestCase):
    def test_city_from_api_timezone_from_geolite(self):
        local = {'country': 'South Korea', 'countryCode': 'KR', 'regionName': 'Daejeon', 'city': 'Daejeon', 'lat': 36.35, 'lon': 127.38,
                 'timezone': 'Asia/Seoul', 'proxy': False, 'hosting': False, 'source': 'GeoLite2'}
        api = {'status': 'success', 'country': 'South Korea', 'countryCode': 'KR', 'regionName': 'Jeollabuk-do', 'city': 'Jeonju',
               'lat': 35.82, 'lon': 127.14, 'timezone': 'Asia/Seoul', 'proxy': False, 'hosting': False}
        class R:
            def json(self): return api
        old_local, old_get = a.geolite_lookup, a.requests.get
        a.geolite_lookup = lambda ip: dict(local)
        a.requests.get = lambda *x, **k: R()
        try:
            a._geo_cache.clear()
            g = REAL_LOOKUP('203.0.113.200')
            self.assertEqual((g['city'], g['lat'], g['timezone'], g['source']), ('Jeonju', 35.82, 'Asia/Seoul', 'GeoLite2+API'))
            api['status'] = 'fail'
            a._geo_cache.clear()
            g = REAL_LOOKUP('203.0.113.201')
            self.assertEqual((g['city'], g['source']), ('Daejeon', 'GeoLite2'))
        finally:
            a.geolite_lookup, a.requests.get = old_local, old_get
            a._geo_cache.clear()


class AdminTest(Base):
    def test_admin_requires_password(self):
        self.assertEqual(self.c.get('/admin').status_code, 401)
        self.assertEqual(self.c.get('/admin', headers=ADMIN).status_code, 200)

    def test_admin_lockout(self):
        bad = {'Authorization': 'Basic ' + base64.b64encode(b'admin:wrong').decode(), 'CF-Connecting-IP': '203.0.113.9'}
        codes = [self.c.get('/api/logs', headers=bad).status_code for _ in range(6)]
        self.assertEqual(codes[:5], [401] * 5)
        self.assertEqual(codes[5], 429)
        good = {**ADMIN, 'CF-Connecting-IP': '203.0.113.9'}
        self.assertEqual(self.c.get('/api/logs', headers=good).status_code, 429)

    def test_csrf_protection(self):
        self.assertEqual(self.c.post('/api/clear', headers=ADMIN).status_code, 403)
        evil = {**ADMIN, **SAME, 'Origin': 'https://evil.example'}
        self.assertEqual(self.c.post('/api/clear', headers=evil).status_code, 403)

    def test_threshold_setting_changes_decision(self):
        self.assertEqual(self.c.post('/api/settings', json={'reauth_line': 30}, headers={**ADMIN, **SAME}).status_code, 400)
        self.c.post('/api/settings', json={'reauth_line': 40}, headers={**ADMIN, **SAME})
        self.assertEqual(a.reauth_line(), 40)
        r = self.scan('121.154.59.135', cid='cid-thresh-001', lang='en-US')
        self.assertEqual(r['action'], 'REAUTH')
        self.c.post('/api/settings', json={'reauth_line': 60}, headers={**ADMIN, **SAME})
        self.assertEqual(a.reauth_line(), 60)

    def test_tuning_report(self):
        t = self.c.get('/api/tuning', headers=ADMIN).get_json()
        row = next(r for r in t['rows'] if r['line'] == 60)
        self.assertEqual(row['attacks'] + row['normals'], len(a.BENCHMARK))
        self.assertGreater(row['detected'], row['false_alarms'])

    def test_simulation_and_csv(self):
        r = self.c.post('/api/simulate', json={'scenario': 'vpn'}, headers={**ADMIN, **SAME}).get_json()
        self.assertEqual(r['status'], 'INTRUSION')
        csv_text = self.c.get('/api/export.csv', headers=ADMIN).get_data(as_text=True)
        self.assertTrue(csv_text.startswith('﻿번호'))


class RetentionTest(Base):
    def test_old_logs_are_deleted(self):
        conn = a.get_conn(); cur = conn.cursor()
        old = a.fmt_time(a.now_kst() - timedelta(days=a.RETENTION_DAYS + 1))
        a.save_log(cur, {'ip': 'x', 'tz': 'Asia/Seoul', 'lat': 1, 'lng': 1, 'city': 'old', 'score': 0, 'platform': 'p',
                         'timestamp': old, 'status': 'SECURE', 'reasons': []})
        conn.commit(); conn.close()
        self.assertGreaterEqual(a.cleanup_old(force=True), 1)
        cities = [l['city'] for l in self.c.get('/api/logs', headers=ADMIN).get_json()]
        self.assertNotIn('old', cities)


if __name__ == '__main__':
    unittest.main(verbosity=2)
