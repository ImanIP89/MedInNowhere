import pytest
import json
import re
from app import app, get_db

@pytest.fixture
def client():
    """ساخت کلاینت تست"""
    app.config['TESTING'] = True
    with app.test_client() as c:
        with app.app_context():
            conn = get_db()
            conn.close()
        yield c

def get_csrf_token(client, url='/'):
    """استخراج CSRF token از صفحه"""
    resp = client.get(url)
    match = re.search(rb'<meta name="csrf-token" content="([^"]+)"', resp.data)
    if match:
        return match.group(1).decode('utf-8')
    return None

def login_as(client, username, password):
    """ورود و ذخیره session در client"""
    token = get_csrf_token(client, '/login')
    rv = client.post('/login', data={
        'username': username,
        'password': password,
        'csrf_token': token
    }, follow_redirects=True)
    # بررسی موفقیت‌آمیز بودن لاگین
    assert rv.status_code == 200
    assert 'MedInNowhere' in rv.data.decode('utf-8')
    return rv

def register_user(client, username, password, full_name='Test User'):
    """ثبت‌نام"""
    token = get_csrf_token(client, '/register')
    return client.post('/register', data={
        'username': username,
        'password': password,
        'full_name': full_name,
        'csrf_token': token
    }, follow_redirects=True)

def post_json(client, url, data, with_csrf=True):
    """ارسال POST JSON"""
    headers = {'Content-Type': 'application/json'}
    if with_csrf:
        token = get_csrf_token(client)
        if token:
            headers['X-CSRF-Token'] = token
    return client.post(url, data=json.dumps(data), content_type='application/json', headers=headers)

# ========== ۱. احراز هویت ==========
def test_register_and_login(client):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE username = ?", ('pytest_user',))
    conn.commit()
    conn.close()

    rv = register_user(client, 'pytest_user', 'Test1234', 'Pytest User')
    assert rv.status_code == 200
    assert 'ورود' in rv.data.decode('utf-8')

    login_as(client, 'pytest_user', 'Test1234')

def test_login_failure(client):
    token = get_csrf_token(client, '/login')
    rv = client.post('/login', data={
        'username': 'admin', 'password': 'wrongpassword', 'csrf_token': token
    }, follow_redirects=True)
    assert 'نام کاربری یا رمز عبور نادرست است' in rv.data.decode('utf-8')

def test_logout(client):
    login_as(client, 'admin', 'admin123')
    client.get('/logout', follow_redirects=True)
    rv = client.get('/dashboard')
    assert rv.status_code == 302

# ========== ۲. تشخیص ==========
def test_api_diseases_public(client):
    rv = client.get('/api/diseases')
    assert rv.status_code == 200
    assert len(json.loads(rv.data)) > 0

def test_patient_diagnose_persian(client):
    login_as(client, 'admin', 'admin123')
    rv = post_json(client, '/api/patient_diagnose', {"symptoms": "سردرد و تهوع"})
    assert rv.status_code == 200
    assert len(json.loads(rv.data)['candidates']) > 0

def test_patient_diagnose_english(client):
    login_as(client, 'admin', 'admin123')
    rv = post_json(client, '/api/patient_diagnose', {"symptoms": "fever and headache"})
    assert rv.status_code == 200
    assert len(json.loads(rv.data)['candidates']) > 0

def test_red_flags(client):
    login_as(client, 'admin', 'admin123')
    rv = post_json(client, '/api/patient_diagnose', {"symptoms": "درد قفسه سینه و تعریق سرد"})
    assert rv.status_code == 200
    data = json.loads(rv.data)
    assert len(data['red_flags']) > 0
    assert any('سکته قلبی' in f['message'] for f in data['red_flags'])

# ========== ۳. تاریخچه ==========
def test_history_and_delete(client):
    login_as(client, 'admin', 'admin123')
    post_json(client, '/api/patient_diagnose', {"symptoms": "کمردرد"})

    rv = client.get('/api/history')
    assert rv.status_code == 200
    data = json.loads(rv.data)
    assert len(data) > 0
    first_id = data[0]['id']

    rv = post_json(client, f'/api/history/delete/{first_id}', {})
    assert rv.status_code == 200
    assert json.loads(rv.data)['message'] == 'حذف شد'

# ========== ۴. چت ==========
def test_chat_search(client):
    login_as(client, 'admin', 'admin123')
    rv = client.get('/api/chat/search/doctor')
    assert rv.status_code == 200
    data = json.loads(rv.data)
    assert len(data) > 0
    assert data[0]['username'] == 'doctor'

def test_chat_messages(client):
    login_as(client, 'admin', 'admin123')
    rv = client.get('/api/chat/messages/doctor')
    assert rv.status_code == 200
    assert isinstance(json.loads(rv.data), list)

# ========== ۵. نسخه ==========
def test_add_and_view_prescription(client):
    """ثبت نسخه و مشاهده از طریق API"""
    login_as(client, 'admin', 'admin123')
    
    # ثبت نسخه
    rv = post_json(client, '/api/prescriptions/add', {
        "patient_id": 2, "medication_name": "Metformin",
        "dosage": "500mg", "instructions": "روزی دو بار"
    })
    assert rv.status_code == 200
    assert 'نسخه ثبت شد' in json.loads(rv.data)['message']

    # چک کردن API نسخه‌ها (نه صفحه HTML)
    rv = client.get('/api/prescriptions')
    assert rv.status_code == 200
    prescriptions = json.loads(rv.data)
    assert len(prescriptions) > 0
    assert any(p['medication_name'] == 'Metformin' for p in prescriptions)
# ========== ۶. داشبورد ==========
def test_dashboard_page(client):
    login_as(client, 'admin', 'admin123')
    rv = client.get('/dashboard')
    assert rv.status_code == 200
    assert 'داشبورد سلامت' in rv.data.decode('utf-8')

def test_dashboard_api(client):
    login_as(client, 'admin', 'admin123')
    rv = client.get('/api/dashboard/stats')
    assert rv.status_code == 200
    assert 'risk_scores' in json.loads(rv.data)

# ========== ۷. امنیت ==========
def test_security_admin_access(client):
    login_as(client, 'admin', 'admin123')
    assert client.get('/security').status_code == 200

def test_security_doctor_denied(client):
    login_as(client, 'doctor', 'doctor123')
    assert client.get('/security').status_code == 403

def test_security_alerts_api(client):
    login_as(client, 'admin', 'admin123')
    rv = client.get('/api/security/alerts')
    assert rv.status_code == 200
    assert isinstance(json.loads(rv.data), list)

# ========== ۸. نقش‌ها ==========
def test_patient_terminal_redirect(client):
    assert client.get('/terminal').status_code == 302

def test_admin_bulk_access(client):
    login_as(client, 'admin', 'admin123')
    assert client.get('/bulk').status_code == 200
    client.get('/logout', follow_redirects=True)
    login_as(client, 'doctor', 'doctor123')
    assert client.get('/bulk').status_code == 403

# ========== ۹. Bulk ==========
def test_bulk_add_with_weight(client):
    login_as(client, 'admin', 'admin123')
    rv = post_json(client, '/api/bulk_add', {
        "diseases": [{
            "name": "Pytest Disease", "urgency": "کم",
            "description": "Test", "treatment": "Rest",
            "symptoms": "سرفه:2,عطسه:1"
        }]
    })
    assert rv.status_code == 200
    assert 'بیماری اضافه شد' in json.loads(rv.data)['message']
    assert any(d['name'] == 'Pytest Disease' for d in json.loads(client.get('/api/diseases').data))

# ========== ۱۰. CSRF ==========
def test_csrf_block(client):
    login_as(client, 'admin', 'admin123')
    rv = post_json(client, '/api/patient_diagnose', {"symptoms": "تب"}, with_csrf=False)
    assert rv.status_code == 403
# ========== ۱۱. تست Brute Force Protection ==========
def test_brute_force_protection(client):
    """تست اینکه Rate Limiting پس از ۵ تلاش ناموفق فعال می‌شود"""
    # ۵ تلاش ناموفق
    for i in range(5):
        token = get_csrf_token(client, '/login')
        rv = client.post('/login', data={
            'username': 'admin',
            'password': f'wrongpassword{i}',
            'csrf_token': token
        }, follow_redirects=True)
        assert 'نام کاربری یا رمز عبور نادرست است' in rv.data.decode('utf-8')
    
    # تلاش ششم — باید ۴۲۹ (Too Many Requests) برگردد
    token = get_csrf_token(client, '/login')
    rv = client.post('/login', data={
        'username': 'admin',
        'password': 'wrongpassword',
        'csrf_token': token
    }, follow_redirects=True)
    assert rv.status_code == 429