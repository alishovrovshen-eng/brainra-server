"""BrainRA — Python kod icra xidməti.

TƏHLÜKƏSİZLİK QEYDİ
Bu xidmət kənardan gələn kodu icra edir. Ona görə uşaq proses:
  • BOŞ ətraf mühitlə işə düşür  → serverdəki heç bir gizli açar görünmür
  • müvəqqəti qovluqda işləyir   → əsl fayl sistemi ilə işi olmur
  • sərt resurs limitləri altında → yaddaş/prosessor/fayl ölçüsü bağlıdır
  • öz proses qrupunda           → vaxt bitəndə bütün nəsli birlikdə öldürülür
Əlavə olaraq IP üzrə sürət limiti var.

QALAN İŞ (tətbiq yeniləndikdən sonra): giriş biletinin (Firebase ID token)
tələb olunması. İndi qoyulsa, köhnə tətbiq versiyalarında Python bölməsi sınar.
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
    return jsonify({'status': 'BrainRA Code Server ishleyir'})


@app.route('/run', methods=['POST'])
def run_code():
    ip = client_ip()
    if rate_limited(ip):
        return jsonify({'output': 'Xeta: Cox sayda sorgu. Bir az sonra yeniden cehd edin.'}), 429

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
