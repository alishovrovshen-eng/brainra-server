"""BrainRA — Python kod icra xidməti.

TƏHLÜKƏSİZLİK QEYDİ
Bu xidmət kənardan gələn kodu icra edir. Ona görə uşaq proses:
  • BOŞ ətraf mühitlə işə düşür  → serverdəki heç bir gizli açar görünmür
  • müvəqqəti qovluqda işləyir   → əsl fayl sistemi ilə işi olmur
  • sərt resurs limitləri altında → yaddaş/prosessor/fayl ölçüsü bağlıdır
  • öz proses qrupunda           → vaxt bitəndə bütün nəsli birlikdə öldürülür
Əlavə olaraq IP üzrə sürət limiti var.

GİRİŞ BİLETİ (Firebase ID token) yoxlanması qurulub, lakin AYRICA AÇARLA
idarə olunur: `REQUIRE_AUTH=1` mühit dəyişəni qoyulana qədər yalnız yoxlanır,
rədd edilmir. Belə etməyin səbəbi: köhnə tətbiq versiyaları bilet göndərmir,
onları bir andın içində kəsmək olmaz. Tələbələr yeniləndən sonra Render-də
həmin dəyişəni 1 et — kod dəyişməyəcək, geri qaytarmaq da bir kliklik işdir.
"""
import os
import sys
import time
import shutil
import signal
import tempfile
import subprocess
import threading
from collections import defaultdict, deque

import jwt
import requests
from cryptography import x509

from flask import Flask, request, jsonify

try:                      # yalnız POSIX (Railway/Linux) — Windows-da yoxdur
    import resource
except ImportError:
    resource = None

app = Flask(__name__)
# Qeyd: CORS qəsdən söndürülüb. Xidməti yalnız mobil tətbiq çağırır, brauzer yox.
# Açıq CORS istənilən saytın ziyarətçilərinin brauzerindən sui-istifadəyə imkan verirdi.

# ── Limitlər ──
TIMEOUT      = 5              # saniyə (əvvəl 10 idi)
MAX_CODE     = 20000          # simvol — göndərilən kodun maksimum ölçüsü
MAX_STDIN    = 10000          # simvol
MAX_OUTPUT   = 20000          # simvol — cavabın maksimum ölçüsü
MEM_LIMIT    = 256 * 1024**2  # 256 MB
FILE_LIMIT   = 1 * 1024**2    # yazıla bilən faylın maksimum ölçüsü
RATE_MINUTE  = 20             # IP başına dəqiqədə
RATE_HOUR    = 200            # IP başına saatda

_hits = defaultdict(deque)
_lock = threading.Lock()


def client_ip():
    fwd = request.headers.get('X-Forwarded-For', '')
    return (fwd.split(',')[0].strip() if fwd else request.remote_addr) or 'unknown'


def rate_limited(ip):
    """Sadə sürüşən pəncərə. Tək nüsxə üçün kifayətdir."""
    now = time.time()
    with _lock:
        q = _hits[ip]
        while q and now - q[0] > 3600:
            q.popleft()
        if len(q) >= RATE_HOUR:
            return True
        if sum(1 for t in q if now - t <= 60) >= RATE_MINUTE:
            return True
        q.append(now)
        if len(_hits) > 5000:                      # yaddaş şişməsin
            stale = [k for k, v in _hits.items() if not v or now - v[-1] > 3600]
            for k in stale[:1000]:
                _hits.pop(k, None)
    return False


# ── Giriş bileti (Firebase ID token) ──
# Admin SDK və xidmət hesabı faylı lazım deyil: bilet Google-un açıq
# açarları ilə yoxlanilir. Açarlar keşlənir, Google onları vaxtaşırı dəyişir.
PROJECT_ID   = os.environ.get('FIREBASE_PROJECT_ID', 'brainra-270b3')
REQUIRE_AUTH = os.environ.get('REQUIRE_AUTH', '0') == '1'
CERT_URL     = ('https://www.googleapis.com/robot/v1/metadata/x509/'
                'securetoken@system.gserviceaccount.com')

_certs = {'keys': {}, 'exp': 0.0}
_cert_lock = threading.Lock()


def google_keys():
    """Google-un imza açarları. Şəbəkə xətasında köhnə açarlarla davam edir."""
    now = time.time()
    with _cert_lock:
        if _certs['keys'] and now < _certs['exp']:
            return _certs['keys']
    try:
        r = requests.get(CERT_URL, timeout=5)
        r.raise_for_status()
        max_age = 3600
        for part in r.headers.get('Cache-Control', '').split(','):
            part = part.strip()
            if part.startswith('max-age='):
                try:
                    max_age = int(part.split('=', 1)[1])
                except ValueError:
                    pass
        keys = {}
        for kid, pem in r.json().items():
            keys[kid] = x509.load_pem_x509_certificate(pem.encode('utf-8')).public_key()
        with _cert_lock:
            _certs['keys'] = keys
            _certs['exp'] = now + max_age
        return keys
    except Exception:
        with _cert_lock:
            return _certs['keys']


def verify_token(header):
    """(ok, uid-və-ya-səbəb)."""
    if not header.startswith('Bearer '):
        return False, 'bilet yoxdur'
    token = header[7:].strip()
    try:
        kid = jwt.get_unverified_header(token).get('kid')
    except Exception:
        return False, 'bilet oxunmadi'
    key = google_keys().get(kid)
    if key is None:
        return False, 'acar tapilmadi'
    try:
        claims = jwt.decode(
            token, key=key, algorithms=['RS256'],
            audience=PROJECT_ID,
            issuer='https://securetoken.google.com/' + PROJECT_ID,
        )
    except Exception:
        return False, 'bilet etibarsizdir'
    uid = claims.get('sub')
    if not uid:
        return False, 'bilet natamamdir'
    return True, uid


def _limits():
    """Uşaq prosesdə — icra başlamazdan ƏVVƏL tətbiq olunur."""
    os.setsid()                                            # öz proses qrupu
    resource.setrlimit(resource.RLIMIT_CPU,   (TIMEOUT, TIMEOUT))
    resource.setrlimit(resource.RLIMIT_AS,    (MEM_LIMIT, MEM_LIMIT))
    resource.setrlimit(resource.RLIMIT_FSIZE, (FILE_LIMIT, FILE_LIMIT))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_CORE,  (0, 0))      # core dump yazma
    try:
        resource.setrlimit(resource.RLIMIT_NPROC, (32, 32))
    except (ValueError, OSError):
        pass


@app.route('/')
def index():
    return jsonify({'status': 'BrainRA Code Server ishleyir',
                    'requireAuth': REQUIRE_AUTH})


@app.route('/run', methods=['POST'])
def run_code():
    ip = client_ip()
    if rate_limited(ip):
        return jsonify({'output': 'Xeta: Cox sayda sorgu. Bir az sonra yeniden cehd edin.'}), 429

    # Giris bileti. REQUIRE_AUTH sondurulu ikan yalniz yoxlanir, redd edilmir.
    ok, _who = verify_token(request.headers.get('Authorization', ''))
    if REQUIRE_AUTH and not ok:
        return jsonify({'output': 'Xeta: Giris teleb olunur. Tetbiqi yeniləyin.'}), 401

    data  = request.get_json(force=True, silent=True) or {}
    code  = str(data.get('code', ''))
    stdin = str(data.get('stdin', ''))

    if not code.strip():
        return jsonify({'output': 'Kod boşdur'})
    if len(code) > MAX_CODE:
        return jsonify({'output': 'Xeta: Kod cox uzundur (max %d simvol).' % MAX_CODE})
    if len(stdin) > MAX_STDIN:
        return jsonify({'output': 'Xeta: Giris melumati cox uzundur (max %d simvol).' % MAX_STDIN})

    workdir = tempfile.mkdtemp(prefix='brainra_')
    # Uşaq prosesə YALNIZ bunlar ötürülür — serverin açarları görünmür
    child_env = {
        'PATH': '/usr/bin:/bin',
        'HOME': workdir,
        'TMPDIR': workdir,
        'LANG': 'C.UTF-8',
        'PYTHONIOENCODING': 'utf-8',
        'PYTHONDONTWRITEBYTECODE': '1',
    }
    proc = None
    try:
        # -I : təcrid rejimi (ətraf mühit dəyişənlərini və istifadəçi paketlərini nəzərə almır)
        proc = subprocess.Popen(
            [sys.executable, '-I', '-c', code],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, cwd=workdir, env=child_env,
            preexec_fn=_limits if (resource and hasattr(os, 'setsid')) else None,
        )
        out, err = proc.communicate(input=stdin, timeout=TIMEOUT)
        output = out or ''
        if err:
            output += ('\n' if output else '') + err
        if len(output) > MAX_OUTPUT:
            output = output[:MAX_OUTPUT] + '\n... (netice cox uzundur, kesildi)'
        return jsonify({'output': output})

    except subprocess.TimeoutExpired:
        # bütün nəsli birlikdə öldür — yalnız valideyni öldürmək kifayət etmir
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        return jsonify({'output': 'Xeta: Vaxt limiti kecdi (%d san).' % TIMEOUT})

    except MemoryError:
        return jsonify({'output': 'Xeta: Yaddas limiti kecdi.'})
    except Exception as e:
        return jsonify({'output': 'Xeta: %s' % type(e).__name__})
    finally:
        if proc and proc.poll() is None:
            try:
                proc.kill()
            except Exception:
                pass
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
