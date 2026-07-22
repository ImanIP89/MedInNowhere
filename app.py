from flask import Flask, render_template, jsonify, request, session, redirect, url_for, abort
from flask_socketio import SocketIO, send, join_room
import sqlite3
import openai
import os
import secrets
import json
import socket
import re
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta

app = Flask(__name__)
socketio = SocketIO(app)

app.secret_key = 'medinnowhere-secret-key-change-in-production'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

DEEPSEEK_API_KEY = "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

def get_db():
    conn = sqlite3.connect('MIN.db', check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    return conn

def ask_deepseek(question):
    openai.api_key = DEEPSEEK_API_KEY
    openai.api_base = "https://api.deepseek.com/v1"
    prompt = f"""تو یک دستیار پزشکی هوشمند و مهربان هستی که به زبان فارسی و روان صحبت می‌کنی.
با توجه به اطلاعات زیر، به سوال بیمار پاسخ بده و توضیح بده که چه اقدامی باید انجام دهد.
همیشه یادآوری کن که این یک نظر اولیه است و باید به پزشک مراجعه کند.

سوال بیمار: {question}

پاسخ تو:"""
    try:
        response = openai.ChatCompletion.create(
            model="deepseek-chat",
            messages=[
                {"role": "system", "content": "شما یک دستیار پزشک هستید و به فارسی جواب می‌دهید."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=500
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"❌ خطا در ارتباط با DeepSeek: {str(e)}"

def translate_text(text, target_lang='English'):
    prompt = f"""Translate the following Persian medical text to {target_lang}.
If the text is not medical, still translate it accurately and naturally.
Text: {text}
Translation:"""
    try:
        openai.api_key = DEEPSEEK_API_KEY
        openai.api_base = "https://api.deepseek.com/v1"
        response = openai.ChatCompletion.create(
            model="deepseek-chat",
            messages=[
                {"role": "system", "content": "You are a helpful medical translator. Always reply in the target language."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            max_tokens=500
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"❌ Translation error: {str(e)}"

def get_disease_symptoms(disease_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT s.name FROM disease_symptoms ds JOIN symptoms s ON ds.symptom_id = s.id WHERE ds.disease_id = ?',
        (disease_id,)
    )
    syms = [row['name'] for row in cursor.fetchall()]
    conn.close()
    return syms

def find_distinguishing_symptom(disease_id1, disease_id2):
    conn = get_db()
    cur = conn.cursor()
    cur.execute('''
        SELECT s.name FROM disease_symptoms ds
        JOIN symptoms s ON ds.symptom_id = s.id
        WHERE ds.disease_id = ? AND s.name NOT IN (
            SELECT s2.name FROM disease_symptoms ds2
            JOIN symptoms s2 ON ds2.symptom_id = s2.id
            WHERE ds2.disease_id = ?
        )
    ''', (disease_id1, disease_id2))
    row = cur.fetchone()
    conn.close()
    return row['name'] if row else None

def get_distinguishing_question(candidates):
    if len(candidates) < 2:
        return None
    conn = get_db()
    cur = conn.cursor()
    cur.execute('''
        SELECT dq.question_text
        FROM diagnostic_questions dq
        WHERE dq.disease_id = ?
          AND dq.symptom_name NOT IN (
              SELECT s2.name FROM disease_symptoms ds2
              JOIN symptoms s2 ON ds2.symptom_id = s2.id
              WHERE ds2.disease_id = ?
          )
        LIMIT 1
    ''', (candidates[0]['id'], candidates[1]['id']))
    row = cur.fetchone()
    conn.close()
    if row:
        return row['question_text']
    symptom = find_distinguishing_symptom(candidates[0]['id'], candidates[1]['id'])
    if symptom:
        return f"آیا شما «{symptom}» را تجربه می‌کنید؟"
    return None

def format_candidates(candidates):
    out = "تشخیص‌های محتمل:\n"
    for c in candidates:
        out += f"🩺 {c['name']} (امتیاز: {c['matched']})\n   شرح: {c['desc']}\n   درمان: {c['treatment']}\n   اورژانس: {c['urgency']}\n"
    return out

def save_diagnosis(user_id, symptoms_text, result, method='normal'):
    conn = get_db()
    cur = conn.cursor()
    cur.execute('INSERT INTO diagnosis_history (user_id, symptoms_text, result, method) VALUES (?, ?, ?, ?)',
                (user_id, symptoms_text, result, method))
    conn.commit()
    conn.close()

# ---------- الگوهای SQL Injection ----------
SQL_INJECTION_PATTERNS = [
    r"(\bUNION\b|\bSELECT\b|\bINSERT\b|\bDELETE\b|\bDROP\b|\bUPDATE\b).*(\bFROM\b|\bINTO\b)",
    r"'--",
    r";--",
    r"/\*.*\*/",
    r"OR\s+1=1",
    r"OR\s+'1'='1'",
    r"xp_cmdshell",
    r"exec\s*\(",
]

def detect_sql_injection(text):
    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False

def log_security_alert(alert_type, ip_address=None, username=None, details=""):
    conn = get_db()
    cur = conn.cursor()
    cur.execute('INSERT INTO security_alerts (alert_type, ip_address, username, details) VALUES (?, ?, ?, ?)',
                (alert_type, ip_address or request.remote_addr, username, details))
    conn.commit()
    conn.close()

def get_recent_failed_logins(ip_address=None, username=None, minutes=10):
    conn = get_db()
    cur = conn.cursor()
    cutoff = (datetime.now() - timedelta(minutes=minutes)).strftime('%Y-%m-%d %H:%M:%S')
    query = 'SELECT COUNT(*) FROM security_alerts WHERE alert_type = ? AND created_at > ?'
    params = ['brute_force', cutoff]
    if ip_address:
        query += ' AND ip_address = ?'
        params.append(ip_address)
    elif username:
        query += ' AND username = ?'
        params.append(username)
    cur.execute(query, params)
    count = cur.fetchone()[0]
    conn.close()
    return count

def check_request_security():
    ip = request.remote_addr
    recent_alerts = get_recent_failed_logins(ip_address=ip, minutes=1)
    if recent_alerts > 20:
        log_security_alert('rate_limit', ip_address=ip, details=f'{recent_alerts} requests in 1 minute')
        return False
    for key, value in request.args.items():
        if detect_sql_injection(value):
            log_security_alert('sql_injection', ip_address=ip, details=f'GET param: {key}={value}')
            return False
    if request.is_json:
        data = request.get_json(silent=True) or {}
        for key, value in data.items():
            if isinstance(value, str) and detect_sql_injection(value):
                log_security_alert('sql_injection', ip_address=ip, details=f'JSON field: {key}={value}')
                return False
    return True

# ---------- CSRF ----------
def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']

def csrf_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method in ['POST', 'PUT', 'DELETE']:
            token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
            if not token or token != session.get('_csrf_token'):
                log_security_alert('csrf_fail', ip_address=request.remote_addr, username=session.get('username'))
                abort(403)
        return f(*args, **kwargs)
    return decorated

@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf_token())

# ---------- Auth ----------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(*roles):
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_role' not in session or session['user_role'] not in roles:
                return "🚫 دسترسی غیرمجاز", 403
            return f(*args, **kwargs)
        return decorated_function
    return wrapper

# ---------- توابع شبکه ----------
def get_hostname():
    return socket.gethostname()

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

def print_server_info():
    hostname = get_hostname()
    local_ip = get_local_ip()
    print("\n" + "="*60)
    print("🩺 MedInNowhere Server is running!")
    print("="*60)
    print(f"📍 Local IP:    http://{local_ip}:5000")
    print(f"📍 Hostname:    http://{hostname}.local:5000")
    print(f"📍 Localhost:   http://127.0.0.1:5000")
    print("="*60)
    print("📡 برای اتصال پایدار PWA از آدرس Hostname استفاده کنید.")
    print("📝 این آدرس‌ها در فایل server.txt نیز ذخیره شدند.\n")
    with open('server.txt', 'w', encoding='utf-8') as f:
        f.write(f"MedInNowhere Server Addresses\n")
        f.write(f"============================\n")
        f.write(f"Local IP:  http://{local_ip}:5000\n")
        f.write(f"Hostname:  http://{hostname}.local:5000\n")
        f.write(f"Localhost: http://127.0.0.1:5000\n")
        f.write(f"============================\n")
        f.write(f"برای اتصال پایدار PWA از Hostname استفاده کنید.\n")

# ---------- Routes ----------
# ---------- Routes ----------
@app.route('/')
def welcome():
    return render_template('welcome.html')

@app.route('/connect')
def connect():
    hostname = get_hostname()
    local_ip = get_local_ip()
    return render_template('connect.html', hostname=hostname, local_ip=local_ip)

@app.route('/terminal')
@login_required
@role_required('doctor', 'admin')
def terminal():
    return render_template('terminal.html')

@app.route('/patient')
@login_required
def patient_form():
    return render_template('patient.html')

@app.route('/xray')
@login_required
def xray_page():
    return render_template('xray.html')

@app.route('/translate')
@login_required
def translate_page():
    return render_template('translate.html')

@app.route('/bulk')
@login_required
@role_required('admin')
def bulk_page():
    return render_template('bulk.html')

@app.route('/history')
@login_required
def history():
    return render_template('history.html')

@app.route('/referrals')
@login_required
@role_required('doctor', 'admin')
def referrals_page():
    return render_template('referrals.html')

@app.route('/reminders')
@login_required
def reminders_page():
    return render_template('reminders.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/chat')
@login_required
def chat_page():
    return render_template('chat.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/security')
@login_required
@role_required('admin')
def security_dashboard():
    return render_template('security.html')

@app.route('/prescriptions')
@login_required
def prescriptions_page():
    return render_template('prescriptions.html')

@app.route('/profile', methods=['GET', 'POST'])
@login_required
@csrf_required
def profile():
    conn = get_db()
    cursor = conn.cursor()
    if request.method == 'POST':
        first_name = request.form['first_name'].strip()
        last_name = request.form['last_name'].strip()
        national_id = request.form['national_id'].strip()
        phone = request.form['phone'].strip()
        medical_history = request.form['medical_history'].strip()
        medications = request.form['medications'].strip()
        cursor.execute('''
            INSERT INTO user_profiles (user_id, first_name, last_name, national_id, phone, medical_history, medications)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                first_name=excluded.first_name,
                last_name=excluded.last_name,
                national_id=excluded.national_id,
                phone=excluded.phone,
                medical_history=excluded.medical_history,
                medications=excluded.medications
        ''', (session['user_id'], first_name, last_name, national_id, phone, medical_history, medications))
        conn.commit()
        conn.close()
        return redirect(url_for('profile'))
    cursor.execute('SELECT * FROM user_profiles WHERE user_id = ?', (session['user_id'],))
    profile_data = cursor.fetchone()
    conn.close()
    return render_template('profile.html', profile=profile_data)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
@csrf_required
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT id, password_hash, role, full_name FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = username
            session['user_role'] = user['role']
            session['full_name'] = user['full_name']
            return redirect(url_for('welcome'))
        log_security_alert('brute_force', username=username, details='Failed login attempt')
        return render_template('login.html', error='نام کاربری یا رمز عبور نادرست است.')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("3 per minute")
@csrf_required
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        full_name = request.form.get('full_name', '').strip()
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
        if cursor.fetchone():
            conn.close()
            return render_template('register.html', error='این نام کاربری قبلاً استفاده شده است.')
        cursor.execute('INSERT INTO users (username, password_hash, role, full_name) VALUES (?, ?, ?, ?)',
                       (username, generate_password_hash(password), 'patient', full_name))
        conn.commit()
        conn.close()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('welcome'))

# ---------- API ----------
@app.route('/api/diseases')
def api_diseases():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT d.name, d.description, d.treatment, d.urgency,
               GROUP_CONCAT(s.name, ', ') as symptoms
        FROM diseases d
        JOIN disease_symptoms ds ON d.id = ds.disease_id
        JOIN symptoms s ON ds.symptom_id = s.id
        GROUP BY d.id
    ''')
    rows = cursor.fetchall()
    conn.close()
    diseases = []
    for row in rows:
        diseases.append({
            "name": row["name"],
            "description": row["description"],
            "treatment": row["treatment"],
            "urgency": row["urgency"],
            "symptoms": row["symptoms"]
        })
    return jsonify(diseases)

@app.route('/api/command', methods=['POST'])
@login_required
@role_required('doctor', 'admin')
@csrf_required
def api_command():
    data = request.get_json()
    cmd = data.get('cmd', '').strip()
    cmd_lower = cmd.lower()
    response = {"output": ""}

    if cmd_lower in ('check', 'show'):
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT d.name, d.urgency, GROUP_CONCAT(s.name, ', ') as symptoms
            FROM diseases d
            JOIN disease_symptoms ds ON d.id = ds.disease_id
            JOIN symptoms s ON ds.symptom_id = s.id
            GROUP BY d.id
        ''')
        rows = cursor.fetchall()
        conn.close()
        if rows:
            output = "🏥 بیماری‌های موجود در دیتابیس:\n"
            for r in rows:
                output += f"🔹 {r['name']} (اورژانس: {r['urgency']})\n   علائم: {r['symptoms']}\n"
        else:
            output = "❌ دیتابیس خالی است."
        response["output"] = output

    elif cmd_lower.startswith('diagnose'):
        parts = cmd.split(' ', 1)
        if len(parts) < 2:
            response["output"] = "❌ نحوه استفاده: diagnose <علائم با کاما> یا diagnose <جمله فارسی>"
        else:
            raw_text = parts[1].strip()
            if ',' in raw_text:
                symptoms_list = [s.strip() for s in raw_text.split(',') if s.strip()]
            else:
                conn = get_db()
                cursor = conn.cursor()
                cursor.execute('SELECT name, name_en FROM symptoms')
                all_symptoms = cursor.fetchall()
                conn.close()
                symptoms_list = []
                for row in all_symptoms:
                    persian_name = row['name']
                    english_name = row['name_en'] or ''
                    if persian_name in raw_text:
                        symptoms_list.append(persian_name)
                    elif english_name and english_name.lower() in raw_text.lower():
                        symptoms_list.append(persian_name)

            if not symptoms_list:
                response["output"] = "❌ هیچ علامت قابل تشخیصی در جمله پیدا نشد."
            else:
                conn = get_db()
                cursor = conn.cursor()
                placeholders = ','.join('?' * len(symptoms_list))
                query = f'''
                    SELECT d.name, d.description, d.treatment, d.urgency,
                           SUM(COALESCE(ds.weight, 1)) as total_weight
                    FROM diseases d
                    JOIN disease_symptoms ds ON d.id = ds.disease_id
                    JOIN symptoms s ON ds.symptom_id = s.id
                    WHERE s.name IN ({placeholders})
                    GROUP BY d.id
                    ORDER BY total_weight DESC
                    LIMIT 1
                '''
                cursor.execute(query, symptoms_list)
                row = cursor.fetchone()
                conn.close()
                if row:
                    output = f"🩺 تشخیص احتمالی: {row['name']} (امتیاز: {row['total_weight']})\n"
                    output += f"   شرح: {row['description']}\n"
                    output += f"   درمان اولیه: {row['treatment']}\n"
                    output += f"   سطح اورژانس: {row['urgency']}"
                else:
                    output = "❌ هیچ بیماری با این علائم پیدا نشد."
            response["output"] = output

    elif cmd_lower.startswith('add'):
        fields = {'name': '', 'urgency': 'کم', 'desc': '', 'treat': '', 'sym': ''}
        params = cmd[3:].strip()
        parts = params.split()
        for part in parts:
            if ':' in part:
                key, val = part.split(':', 1)
                key = key.lower()
                if key in fields:
                    fields[key] = val.strip()
        if not fields['name'] or not fields['sym']:
            response["output"] = ("❌ حداقل name و sym الزامی است.\n"
                                  "فرمت: add name:نام_بیماری sym:علامت۱,علامت۲ urgency:کم/متوسط/بالا desc:توضیح treat:درمان")
        else:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('INSERT INTO diseases (name, description, treatment, urgency) VALUES (?, ?, ?, ?)',
                           (fields['name'], fields['desc'], fields['treat'], fields['urgency']))
            disease_id = cursor.lastrowid
            symptom_names = [s.strip() for s in fields['sym'].split(',') if s.strip()]
            for sym in symptom_names:
                cursor.execute('INSERT OR IGNORE INTO symptoms (name) VALUES (?)', (sym,))
                cursor.execute('SELECT id FROM symptoms WHERE name = ?', (sym,))
                sym_id = cursor.fetchone()[0]
                cursor.execute('INSERT OR IGNORE INTO disease_symptoms (disease_id, symptom_id) VALUES (?, ?)',
                               (disease_id, sym_id))
            conn.commit()
            conn.close()
            response["output"] = f"✅ بیماری «{fields['name']}» با موفقیت به دیتابیس اضافه شد.\nعلائم: {fields['sym']}"

    elif cmd_lower.startswith('ask'):
        parts = cmd.split(' ', 1)
        if len(parts) < 2:
            response["output"] = "❌ نحوه استفاده: ask سوال خود را بنویسید"
        else:
            question = parts[1].strip()
            answer = ask_deepseek(question)
            response["output"] = f"🤖 پاسخ DeepSeek:\n{answer}"

    elif cmd_lower.startswith('translate'):
        parts = cmd.split(' ', 1)
        if len(parts) < 2:
            response["output"] = "❌ نحوه استفاده: translate <متن> یا translate to <زبان>: <متن>"
        else:
            text_part = parts[1].strip()
            target = 'English'
            if text_part.lower().startswith('to '):
                colon_idx = text_part.find(':')
                if colon_idx == -1:
                    response["output"] = "❌ فرمت: translate to French: Bonjour"
                else:
                    target = text_part[3:colon_idx].strip()
                    text = text_part[colon_idx+1:].strip()
                    if not text:
                        response["output"] = "❌ متنی برای ترجمه وارد نشده."
                    else:
                        translation = translate_text(text, target)
                        response["output"] = f"🌐 ترجمه به {target}:\n{translation}"
            else:
                translation = translate_text(text_part, 'English')
                response["output"] = f"🌐 ترجمه به انگلیسی:\n{translation}"

    elif cmd_lower.startswith('delete'):
        parts = cmd.split(' ', 1)
        if len(parts) < 2:
            response["output"] = "❌ نحوه استفاده: delete <نام دقیق بیماری>"
        else:
            name_to_delete = parts[1].strip()
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM diseases WHERE name = ?', (name_to_delete,))
            row = cursor.fetchone()
            if not row:
                response["output"] = f"❌ بیماری با نام '{name_to_delete}' پیدا نشد."
            else:
                disease_id = row[0]
                cursor.execute('DELETE FROM disease_symptoms WHERE disease_id = ?', (disease_id,))
                cursor.execute('DELETE FROM diseases WHERE id = ?', (disease_id,))
                conn.commit()
                conn.close()
                response["output"] = f"✅ بیماری '{name_to_delete}' با موفقیت حذف شد."

    elif cmd_lower.startswith('guided'):
        response["output"] = ("⚡ تشخیص گام‌به‌گام فقط از طریق فرم بیمار (Patient Form) در دسترس است."
                              " لطفاً از آنجا استفاده کنید.")

    else:
        response["output"] = "❌ دستور نامعتبر. دستورات: check, diagnose, add, ask, translate, delete, guided"

    return jsonify(response)

@app.route('/api/patient_diagnose', methods=['POST'])
@login_required
@csrf_required
def patient_diagnose():
    data = request.get_json()
    raw_text = data.get('symptoms', '').strip()
    if not raw_text:
        return jsonify({"error": "لطفاً علائم خود را وارد کنید."})

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT name, name_en FROM symptoms')
    all_symptoms = cursor.fetchall()
    conn.close()

    found_symptoms = []
    for row in all_symptoms:
        persian_name = row['name']
        english_name = row['name_en'] or ''
        if persian_name in raw_text:
            found_symptoms.append(persian_name)
        elif english_name and english_name.lower() in raw_text.lower():
            found_symptoms.append(persian_name)

    if not found_symptoms:
        return jsonify({"error": "متأسفانه هیچ علامتی در متن شما پیدا نشد. لطفاً واضح‌تر توضیح دهید."})

    # ---------- Red Flags ----------
    red_flags_found = []
    conn = get_db()
    cursor = conn.cursor()
    for symptom in found_symptoms:
        cursor.execute('SELECT urgency_message, severity FROM red_flags WHERE symptom_name = ?', (symptom,))
        flag = cursor.fetchone()
        if flag:
            red_flags_found.append({
                "symptom": symptom,
                "message": flag['urgency_message'],
                "severity": flag['severity']
            })
    conn.close()

    conn = get_db()
    cursor = conn.cursor()
    placeholders = ','.join('?' * len(found_symptoms))
    query = f'''
        SELECT d.name, d.description, d.treatment, d.urgency,
               SUM(COALESCE(ds.weight, 1)) as total_weight
        FROM diseases d
        JOIN disease_symptoms ds ON d.id = ds.disease_id
        JOIN symptoms s ON ds.symptom_id = s.id
        WHERE s.name IN ({placeholders})
        GROUP BY d.id
        ORDER BY total_weight DESC
        LIMIT 5
    '''
    cursor.execute(query, found_symptoms)
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        return jsonify({"error": "بیماری منطبق با علائم شما یافت نشد. لطفاً با پزشک مشورت کنید."})

    candidates = []
    for row in rows:
        candidates.append({
            "name": row["name"],
            "description": row["description"],
            "treatment": row["treatment"],
            "urgency": row["urgency"],
            "matched": row["total_weight"]
        })

    result_json = json.dumps(candidates, ensure_ascii=False)
    save_diagnosis(session['user_id'], raw_text, result_json, method='normal')

    return jsonify({
        "candidates": candidates,
        "symptoms_found": found_symptoms,
        "red_flags": red_flags_found
    })

# ---------- Guided Diagnosis ----------
@app.route('/api/guided_start', methods=['POST'])
@login_required
@csrf_required
def guided_start():
    data = request.get_json()
    raw_text = data.get('symptoms', '').strip()
    if not raw_text:
        return jsonify({"error": "لطفاً علائم اولیه را توضیح دهید."})

    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT name, name_en FROM symptoms')
    all_symptoms = cur.fetchall()
    conn.close()
    found = []
    for row in all_symptoms:
        persian_name = row['name']
        english_name = row['name_en'] or ''
        if persian_name in raw_text:
            found.append(persian_name)
        elif english_name and english_name.lower() in raw_text.lower():
            found.append(persian_name)

    if not found:
        return jsonify({"error": "هیچ علامتی شناسایی نشد."})

    conn = get_db()
    cur = conn.cursor()
    placeholders = ','.join('?' * len(found))
    cur.execute(f'''
        SELECT d.id, d.name, d.description, d.treatment, d.urgency,
               SUM(COALESCE(ds.weight, 1)) as total_weight
        FROM diseases d
        JOIN disease_symptoms ds ON d.id = ds.disease_id
        JOIN symptoms s ON ds.symptom_id = s.id
        WHERE s.name IN ({placeholders})
        GROUP BY d.id
        ORDER BY total_weight DESC
        LIMIT 5
    ''', found)
    candidates = cur.fetchall()
    conn.close()

    if not candidates:
        return jsonify({"error": "بیماری منطبقی یافت نشد."})

    session['guided_candidates'] = [{"id": c['id'], "name": c['name'], "desc": c['description'],
                                      "treatment": c['treatment'], "urgency": c['urgency'], "matched": c['total_weight']}
                                     for c in candidates]
    session['guided_found'] = found
    session['guided_step'] = 1
    session['guided_symptoms_text'] = raw_text

    question = get_distinguishing_question(session['guided_candidates'])
    if question:
        return jsonify({"question": question})
    else:
        result_text = format_candidates(session['guided_candidates'])
        save_diagnosis(session['user_id'], raw_text, result_text, method='guided')
        session.pop('guided_candidates', None)
        return jsonify({"result": result_text})

@app.route('/api/guided_answer', methods=['POST'])
@login_required
@csrf_required
def guided_answer():
    data = request.get_json()
    answer = data.get('answer', '').strip().lower()
    if 'guided_candidates' not in session:
        return jsonify({"error": "جلسه‌ای فعال نیست."})

    candidates = session['guided_candidates']
    if len(candidates) < 2:
        result_text = format_candidates(candidates)
        save_diagnosis(session['user_id'], session.get('guided_symptoms_text', ''), result_text, method='guided')
        session.pop('guided_candidates', None)
        return jsonify({"result": result_text})

    question = get_distinguishing_question(candidates)
    if not question:
        result_text = format_candidates(candidates)
        save_diagnosis(session['user_id'], session.get('guided_symptoms_text', ''), result_text, method='guided')
        session.pop('guided_candidates', None)
        return jsonify({"result": result_text})

    symptom = find_distinguishing_symptom(candidates[0]['id'], candidates[1]['id'])
    if not symptom:
        result_text = format_candidates(candidates)
        save_diagnosis(session['user_id'], session.get('guided_symptoms_text', ''), result_text, method='guided')
        session.pop('guided_candidates', None)
        return jsonify({"result": result_text})

    if answer in ['بله', 'yes', 'y']:
        filtered = [c for c in candidates if symptom in get_disease_symptoms(c['id'])]
    else:
        filtered = [c for c in candidates if symptom not in get_disease_symptoms(c['id'])]

    if len(filtered) == 1:
        result_text = format_candidates(filtered)
        save_diagnosis(session['user_id'], session.get('guided_symptoms_text', ''), result_text, method='guided')
        session.pop('guided_candidates', None)
        return jsonify({"result": result_text})
    elif len(filtered) == 0:
        result_text = "تشخیص قطعی ممکن نیست."
        save_diagnosis(session['user_id'], session.get('guided_symptoms_text', ''), result_text, method='guided')
        session.pop('guided_candidates', None)
        return jsonify({"result": result_text})
    else:
        session['guided_candidates'] = filtered
        next_question = get_distinguishing_question(filtered)
        if next_question:
            return jsonify({"question": next_question})
        else:
            result_text = format_candidates(filtered)
            save_diagnosis(session['user_id'], session.get('guided_symptoms_text', ''), result_text, method='guided')
            session.pop('guided_candidates', None)
            return jsonify({"result": result_text})

# ---------- History, Referrals, Reminders, Bulk, Translate, AI ----------
@app.route('/api/history')
@login_required
def get_history():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, symptoms_text, result, method, created_at FROM diagnosis_history WHERE user_id = ? ORDER BY created_at DESC', (session['user_id'],))
    rows = cursor.fetchall()
    conn.close()
    history = []
    for row in rows:
        history.append({"id": row["id"], "symptoms_text": row["symptoms_text"], "result": row["result"], "method": row["method"], "created_at": row["created_at"]})
    return jsonify(history)

@app.route('/api/history/delete/<int:history_id>', methods=['POST'])
@login_required
@csrf_required
def delete_history(history_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM diagnosis_history WHERE id = ? AND user_id = ?', (history_id, session['user_id']))
    conn.commit()
    conn.close()
    return jsonify({"message": "حذف شد"})

@app.route('/api/doctors')
@login_required
def get_doctors():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, full_name FROM users WHERE role = ?', ('doctor',))
    doctors = [{"id": r["id"], "full_name": r["full_name"] or "پزشک"} for r in cursor.fetchall()]
    conn.close()
    return jsonify(doctors)

@app.route('/api/refer', methods=['POST'])
@login_required
@csrf_required
def refer_patient():
    data = request.get_json()
    diagnosis_id = data.get('diagnosis_id')
    doctor_id = data.get('doctor_id')
    if not diagnosis_id or not doctor_id:
        return jsonify({"error": "پارامتر ناقص"}), 400
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT symptoms_text, result FROM diagnosis_history WHERE id = ? AND user_id = ?', (diagnosis_id, session['user_id']))
    diag = cursor.fetchone()
    if not diag:
        conn.close()
        return jsonify({"error": "تشخیص یافت نشد"}), 404
    cursor.execute('INSERT INTO referrals (patient_id, doctor_id, diagnosis_id, symptoms_text, diagnosis_text) VALUES (?,?,?,?,?)',
                   (session['user_id'], doctor_id, diagnosis_id, diag['symptoms_text'], diag['result']))
    conn.commit()
    conn.close()
    return jsonify({"message": "ارجاع ثبت شد"})

@app.route('/api/referrals')
@login_required
@role_required('doctor', 'admin')
def get_referrals():
    conn = get_db()
    cursor = conn.cursor()
    if session['user_role'] == 'admin':
        cursor.execute('''SELECT r.id, r.patient_id, r.symptoms_text, r.diagnosis_text, r.doctor_note, r.status, r.created_at,
                                 u.full_name as patient_name
                          FROM referrals r JOIN users u ON r.patient_id = u.id ORDER BY r.created_at DESC''')
    else:
        cursor.execute('''SELECT r.id, r.patient_id, r.symptoms_text, r.diagnosis_text, r.doctor_note, r.status, r.created_at,
                                 u.full_name as patient_name
                          FROM referrals r JOIN users u ON r.patient_id = u.id
                          WHERE r.doctor_id = ? ORDER BY r.created_at DESC''', (session['user_id'],))
    rows = cursor.fetchall()
    conn.close()
    referrals = []
    for row in rows:
        referrals.append({
            "id": row["id"],
            "patient_id": row["patient_id"],
            "patient_name": row["patient_name"],
            "symptoms_text": row["symptoms_text"],
            "diagnosis_text": row["diagnosis_text"],
            "doctor_note": row["doctor_note"],
            "status": row["status"],
            "created_at": row["created_at"]
        })
    return jsonify(referrals)

@app.route('/api/referrals/<int:referral_id>/note', methods=['POST'])
@login_required
@role_required('doctor', 'admin')
@csrf_required
def add_note(referral_id):
    data = request.get_json()
    note = data.get('note', '')
    status = data.get('status', 'reviewed')
    conn = get_db()
    cursor = conn.cursor()
    if session['user_role'] != 'admin':
        cursor.execute('SELECT doctor_id FROM referrals WHERE id = ?', (referral_id,))
        ref = cursor.fetchone()
        if not ref or ref['doctor_id'] != session['user_id']:
            conn.close()
            return jsonify({"error": "غیرمجاز"}), 403
    cursor.execute('UPDATE referrals SET doctor_note = ?, status = ? WHERE id = ?', (note, status, referral_id))
    conn.commit()
    conn.close()
    return jsonify({"message": "ذخیره شد"})

@app.route('/api/reminders')
@login_required
def get_reminders():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, medication_name, reminder_time FROM medication_reminders WHERE user_id = ? ORDER BY reminder_time', (session['user_id'],))
    reminders = [{"id": r["id"], "medication_name": r["medication_name"], "reminder_time": r["reminder_time"]} for r in cursor.fetchall()]
    conn.close()
    return jsonify(reminders)

@app.route('/api/reminders/add', methods=['POST'])
@login_required
@csrf_required
def add_reminder():
    data = request.get_json()
    medication_name = data.get('medication_name', '').strip()
    reminder_time = data.get('reminder_time', '').strip()
    if not medication_name or not reminder_time:
        return jsonify({"error": "نام دارو و زمان الزامی است."}), 400
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO medication_reminders (user_id, medication_name, reminder_time) VALUES (?, ?, ?)',
                   (session['user_id'], medication_name, reminder_time))
    conn.commit()
    conn.close()
    return jsonify({"message": "یادآور اضافه شد."})

@app.route('/api/reminders/delete/<int:reminder_id>', methods=['POST'])
@login_required
@csrf_required
def delete_reminder(reminder_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM medication_reminders WHERE id = ? AND user_id = ?', (reminder_id, session['user_id']))
    conn.commit()
    conn.close()
    return jsonify({"message": "حذف شد"})

@app.route('/api/bulk_add', methods=['POST'])
@login_required
@role_required('admin')
@csrf_required
def api_bulk_add():
    data = request.get_json()
    diseases = data.get('diseases', [])
    if not diseases:
        return jsonify({"message": "❌ هیچ داده‌ای ارسال نشد."})
    conn = get_db()
    cursor = conn.cursor()
    added = 0
    for d in diseases:
        name = d.get('name', '').strip()
        urgency = d.get('urgency', 'کم').strip()
        desc = d.get('description', '').strip()
        treat = d.get('treatment', '').strip()
        symptoms_str = d.get('symptoms', '').strip()
        if not name or not symptoms_str:
            continue
        cursor.execute('INSERT INTO diseases (name, description, treatment, urgency) VALUES (?,?,?,?)',
                       (name, desc, treat, urgency))
        disease_id = cursor.lastrowid
        symptom_parts = [s.strip() for s in symptoms_str.split(',') if s.strip()]
        for part in symptom_parts:
            if ':' in part:
                sym_name, weight_str = part.split(':', 1)
                sym_name = sym_name.strip()
                try:
                    weight = int(weight_str.strip())
                except:
                    weight = 1
            else:
                sym_name = part
                weight = 1
            cursor.execute('INSERT OR IGNORE INTO symptoms (name) VALUES (?)', (sym_name,))
            cursor.execute('SELECT id FROM symptoms WHERE name = ?', (sym_name,))
            sym_id = cursor.fetchone()[0]
            cursor.execute('INSERT OR IGNORE INTO disease_symptoms (disease_id, symptom_id, weight) VALUES (?,?,?)',
                           (disease_id, sym_id, weight))
        added += 1
    conn.commit()
    conn.close()
    return jsonify({"message": f"✅ {added} بیماری اضافه شد."})

@app.route('/api/translate', methods=['POST'])
def api_translate():
    data = request.get_json()
    text = data.get('text', '').strip()
    target = data.get('target', 'English').strip()
    if not text:
        return jsonify({"error": "متن وارد نشده."})
    translation = translate_text(text, target)
    return jsonify({"translation": translation})

@app.route('/api/ai_ask', methods=['POST'])
def ai_ask():
    data = request.get_json()
    question = data.get('question', '').strip()
    if not question:
        return jsonify({"error": "سوال خالی است."})
    answer = ask_deepseek(question)
    return jsonify({"answer": answer})

# ---------- Dashboard APIs ----------
@app.route('/api/dashboard/stats')
@login_required
def dashboard_stats():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) as total FROM diagnosis_history WHERE user_id = ?', (session['user_id'],))
    total_diagnoses = cursor.fetchone()['total']
    
    cursor.execute('SELECT COUNT(*) as total FROM diagnosis_history WHERE user_id = ? AND created_at >= datetime("now", "-30 days")', (session['user_id'],))
    recent_diagnoses = cursor.fetchone()['total']
    
    cursor.execute('SELECT result FROM diagnosis_history WHERE user_id = ?', (session['user_id'],))
    rows = cursor.fetchall()
    
    disease_freq = {}
    urgency_counts = {'کم': 0, 'متوسط': 0, 'بالا': 0}
    for row in rows:
        try:
            candidates = json.loads(row['result'])
            for c in candidates:
                name = c['name']
                disease_freq[name] = disease_freq.get(name, 0) + 1
                urgency = c.get('urgency', 'کم')
                urgency_counts[urgency] = urgency_counts.get(urgency, 0) + 1
        except:
            pass
    
    top_diseases = sorted(disease_freq.items(), key=lambda x: x[1], reverse=True)[:5]
    
    monthly_diagnoses = []
    for i in range(5, -1, -1):
        cursor.execute('''
            SELECT COUNT(*) as total FROM diagnosis_history
            WHERE user_id = ? AND strftime("%Y-%m", created_at) = strftime("%Y-%m", datetime("now", ?))
        ''', (session['user_id'], f'-{i} months'))
        count = cursor.fetchone()['total']
        month = (datetime.now() - timedelta(days=30*i)).strftime('%Y-%m')
        monthly_diagnoses.append({"month": month, "count": count})
    
    risk_scores = calculate_risk_scores()
    
    conn.close()
    
    return jsonify({
        "total_diagnoses": total_diagnoses,
        "recent_diagnoses": recent_diagnoses,
        "top_diseases": [{"name": d, "count": c} for d, c in top_diseases],
        "urgency_distribution": urgency_counts,
        "monthly_diagnoses": monthly_diagnoses,
        "risk_scores": risk_scores
    })

def calculate_risk_scores():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM user_profiles WHERE user_id = ?', (session['user_id'],))
    profile = cursor.fetchone()
    conn.close()
    
    risks = {"diabetes": 0, "hypertension": 0, "osteoarthritis": 0, "cardiovascular": 0}
    
    if not profile:
        return risks
    
    age_estimate = 45
    medical_history = (profile['medical_history'] or '').lower()
    medications = (profile['medications'] or '').lower()
    
    diabetes_risk = 5
    if 'دیابت' in medical_history or 'قند' in medical_history: diabetes_risk += 30
    if 'متفورمین' in medications or 'انسولین' in medications: diabetes_risk += 25
    if age_estimate > 45: diabetes_risk += 10
    risks['diabetes'] = min(diabetes_risk, 95)
    
    bp_risk = 10
    if 'فشار خون' in medical_history or 'پرفشاری' in medical_history: bp_risk += 35
    if 'لسارتان' in medications or 'آملودیپین' in medications: bp_risk += 25
    if age_estimate > 50: bp_risk += 10
    risks['hypertension'] = min(bp_risk, 95)
    
    oa_risk = 5
    if 'آرتروز' in medical_history or 'زانو' in medical_history or 'کمر' in medical_history: oa_risk += 30
    if 'استئوآرتریت' in medical_history or 'درد مفاصل' in medical_history: oa_risk += 25
    if age_estimate > 50: oa_risk += 15
    risks['osteoarthritis'] = min(oa_risk, 95)
    
    cv_risk = 5
    if 'قلب' in medical_history or 'سکته' in medical_history: cv_risk += 35
    if 'کلسترول' in medications or 'آتورواستاتین' in medications: cv_risk += 20
    if 'دیابت' in medical_history: cv_risk += 15
    if age_estimate > 50: cv_risk += 10
    risks['cardiovascular'] = min(cv_risk, 95)
    
    return risks

# ---------- Security APIs ----------
@app.route('/api/security/alerts')
@login_required
@role_required('admin')
def get_security_alerts():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM security_alerts ORDER BY created_at DESC LIMIT 100')
    alerts = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return jsonify(alerts)

# ---------- Chat APIs ----------
@app.route('/api/chat/search/<username>')
@login_required
def search_user(username):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, full_name, role FROM users WHERE username LIKE ? AND id != ?',
                   (f'%{username}%', session['user_id']))
    users = [{"id": r["id"], "username": r["username"], "full_name": r["full_name"], "role": r["role"]}
             for r in cursor.fetchall()]
    conn.close()
    return jsonify(users)

@app.route('/api/chat/messages/<username>')
@login_required
def get_chat_messages(username):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT cm.id, cm.sender_id, cm.message, cm.created_at, u.username as sender_username
        FROM chat_messages cm
        JOIN users u ON cm.sender_id = u.id
        WHERE (cm.sender_id = ? AND cm.receiver_username = ?)
           OR (cm.receiver_username = ? AND cm.sender_id = (SELECT id FROM users WHERE username = ?))
        ORDER BY cm.created_at ASC
    ''', (session['user_id'], username, session['username'], username))
    messages = [{"id": r["id"], "sender_id": r["sender_id"], "sender_username": r["sender_username"],
                 "message": r["message"], "created_at": r["created_at"]} for r in cursor.fetchall()]
    conn.close()
    return jsonify(messages)

# ---------- e-Prescription APIs ----------
@app.route('/api/prescriptions')
@login_required
def get_prescriptions():
    conn = get_db()
    cursor = conn.cursor()
    if session['user_role'] in ('doctor', 'admin'):
        cursor.execute('''
            SELECT p.id, p.medication_name, p.dosage, p.instructions, p.status, p.created_at,
                   u.full_name as patient_name
            FROM prescriptions p
            JOIN users u ON p.patient_id = u.id
            WHERE p.doctor_id = ?
            ORDER BY p.created_at DESC
        ''', (session['user_id'],))
    else:
        cursor.execute('''
            SELECT p.id, p.medication_name, p.dosage, p.instructions, p.status, p.created_at,
                   (SELECT full_name FROM users WHERE id = p.doctor_id) as doctor_name
            FROM prescriptions p
            WHERE p.patient_id = ?
            ORDER BY p.created_at DESC
        ''', (session['user_id'],))
    rows = cursor.fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/prescriptions/add', methods=['POST'])
@login_required
@role_required('doctor', 'admin')
@csrf_required
def add_prescription():
    data = request.get_json()
    patient_id = data.get('patient_id')
    medication_name = data.get('medication_name', '').strip()
    dosage = data.get('dosage', '').strip()
    instructions = data.get('instructions', '').strip()
    
    if not patient_id or not medication_name:
        return jsonify({"error": "بیمار و نام دارو الزامی است."}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO prescriptions (patient_id, doctor_id, medication_name, dosage, instructions) VALUES (?, ?, ?, ?, ?)',
                   (patient_id, session['user_id'], medication_name, dosage, instructions))
    conn.commit()
    conn.close()
    return jsonify({"message": "نسخه ثبت شد."})

@app.route('/api/prescriptions/deactivate/<int:prescription_id>', methods=['POST'])
@login_required
@role_required('doctor', 'admin')
@csrf_required
def deactivate_prescription(prescription_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('UPDATE prescriptions SET status = ? WHERE id = ? AND doctor_id = ?',
                   ('inactive', prescription_id, session['user_id']))
    conn.commit()
    conn.close()
    return jsonify({"message": "نسخه غیرفعال شد."})

# ---------- SocketIO Events ----------
@socketio.on('join')
def handle_join(data):
    username = data.get('username', '')
    if username:
        room = f"chat_{min(session['username'], username)}_{max(session['username'], username)}"
        join_room(room)
        session['current_room'] = room
        session['chat_with'] = username
        send(f'{session.get("username", "ناشناس")} وارد چت شد.', room=room)

@socketio.on('message')
def handle_message(data):
    msg = data.get('msg', '').strip()
    receiver = session.get('chat_with', '')
    room = session.get('current_room', '')
    sender_username = session.get('username', 'ناشناس')
    
    if msg and receiver and room:
        conn = get_db()
        cur = conn.cursor()
        cur.execute('INSERT INTO chat_messages (sender_id, receiver_username, message) VALUES (?, ?, ?)',
                    (session['user_id'], receiver, msg))
        conn.commit()
        conn.close()
        send(f'{sender_username}: {msg}', room=room)

if __name__ == '__main__':
    print_server_info()
    socketio.run(app, debug=False, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)