import subprocess
import sys
import os
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

TIMEOUT = 10  # saniyə

@app.route('/')
def index():
    return jsonify({'status': 'BrainRA Code Server ishleyir'})

@app.route('/run', methods=['POST'])
def run_code():
    data = request.get_json(force=True)
    code = data.get('code', '')
    stdin = data.get('stdin', '')

    if not code.strip():
        return jsonify({'output': 'Kod boşdur'})

    try:
        result = subprocess.run(
            [sys.executable, '-c', code],
            input=stdin,
            capture_output=True,
            text=True,
            timeout=TIMEOUT
        )
        output = result.stdout
        if result.stderr:
            output += ('\n' if output else '') + result.stderr
        return jsonify({'output': output or ''})
    except subprocess.TimeoutExpired:
        return jsonify({'output': f'Xeta: Vaxt limiti kecdi ({TIMEOUT} san).'})
    except Exception as e:
        return jsonify({'output': f'Xeta: {str(e)}'})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
