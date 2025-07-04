from flask import Flask, request, jsonify, session, send_from_directory
from flask_pymongo import PyMongo
from flask_mail import Mail, Message
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from bson import ObjectId
from datetime import timedelta, datetime
from dotenv import load_dotenv
import os, random

# Load environment variables from .env
load_dotenv()

app = Flask(__name__)

# === 🛡️ CORS Setup ===
CORS(app, origins=[
    "https://hostel69.onrender.com",  # ✅ Include actual frontend domain if different
], supports_credentials=True)

# === 🔐 Security + Session Config ===
app.secret_key = os.getenv('SECRET_KEY')
app.permanent_session_lifetime = timedelta(days=1)
app.config['SESSION_COOKIE_SAMESITE'] = 'None'
app.config['SESSION_COOKIE_SECURE'] = True

# === 🛠️ Environment Config ===
app.config['MONGO_URI'] = os.getenv('MONGO_URI')
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', '/tmp/uploads')

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Ensure upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# === 📦 Mongo & Mail ===
mongo = PyMongo(app)
mail = Mail(app)
users_collection = mongo.db.user
complaints_collection = mongo.db.complaints
admin_id_collection = mongo.db.id
otp_store = {}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# === 🔐 Registration ===
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'student')
    email = data.get('email')
    admin_id = data.get('adminId')

    if not all([username, password, email]):
        return jsonify({'message': 'Missing required fields'}), 400

    if users_collection.find_one({'username': username}):
        return jsonify({'message': 'User already exists'}), 409

    if role == 'admin':
        if not admin_id or not admin_id.isdigit() or len(admin_id) != 6:
            return jsonify({'message': 'Valid 6-digit Admin ID required'}), 400
        if not admin_id_collection.find_one({'id': admin_id.strip()}):
            return jsonify({'message': 'Admin ID not found'}), 403

    otp = str(random.randint(100000, 999999))
    otp_store[username] = {
        'otp': otp,
        'user': {
            'username': username,
            'password': generate_password_hash(password),
            'role': role,
            'email': email
        }
    }

    try:
        msg = Message('Your OTP Code', sender=app.config['MAIL_USERNAME'], recipients=[email])
        msg.body = f'Your OTP for registration is: {otp}'
        mail.send(msg)
    except Exception as e:
        print("Mail send failed:", e)
        return jsonify({'message': 'Failed to send OTP'}), 500

    return jsonify({'message': 'OTP sent to email'}), 200

# === ✅ Verify OTP ===
@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    username = data.get('username')
    entered_otp = data.get('otp')

    record = otp_store.get(username)
    if not record:
        return jsonify({'message': 'No OTP session found'}), 400
    if entered_otp == record['otp']:
        users_collection.insert_one(record['user'])
        otp_store.pop(username, None)
        return jsonify({'message': 'Registration successful'}), 201
    return jsonify({'message': 'Invalid OTP'}), 403

# === 🔑 Login ===
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role')

    user = users_collection.find_one({'username': username})
    if user and check_password_hash(user['password'], password):
        if role and role != user.get('role', '').lower():
            return jsonify({'message': 'Role does not match'}), 401

        session['username'] = username
        session['role'] = user.get('role', 'student')
        redirect = '/dashboard.html' if session['role'] == 'student' else '/warden.html'
        return jsonify({'message': 'Login successful', 'redirect': redirect}), 200

    return jsonify({'message': 'Invalid credentials'}), 401

# === 🚪 Logout ===
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    session.pop('role', None)
    return jsonify({'message': 'Logged out successfully'}), 200

# === 📝 Submit Complaint ===
@app.route('/submit_complaint', methods=['POST'])
def submit_complaint():
    if 'username' not in session:
        return jsonify({'message': 'Please login first'}), 401

    name = request.form.get('name')
    rollno = request.form.get('rollno')
    year = request.form.get('year')
    branch = request.form.get('branch')
    title = request.form.get('title') or request.form.get('complaintTitle')
    text = request.form.get('text') or request.form.get('complaintText')
    room = request.form.get('room') or request.form.get('roomNo')
    hostel = request.form.get('hostel')
    date = request.form.get('date') or datetime.now().isoformat()

    required_fields = [name, rollno, year, branch, title, text, room, hostel, date]
    if not all(required_fields):
        return jsonify({'message': 'Missing data'}), 400

    image_url = None
    if 'image' in request.files:
        file = request.files['image']
        if file.filename and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            image_url = f'/uploads/{filename}'

    complaint = {
        'username': session['username'],
        'email': users_collection.find_one({'username': session['username']})['email'],
        'name': name,
        'rollno': rollno,
        'year': year,
        'branch': branch,
        'title': title,
        'text': text,
        'room': room,
        'hostel': hostel,
        'date': date,
        'status': 'Open',
        'image_url': image_url
    }

    complaints_collection.insert_one(complaint)
    return jsonify({'message': 'Complaint submitted successfully'}), 200

# === 🖼️ Serve Uploaded Files ===
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# === 📋 Fetch Complaints ===
@app.route('/api/complaints', methods=['GET'])
def get_all_complaints():
    if 'username' not in session:
        return jsonify({'message': 'Please login first'}), 401
    user = users_collection.find_one({'username': session['username']})
    if not user:
        return jsonify({'message': 'User not found'}), 401
    if user.get('role') == 'admin':
        complaints = list(complaints_collection.find())
    else:
        complaints = list(complaints_collection.find({'username': session['username']}))
    for c in complaints:
        c['_id'] = str(c['_id'])
        c.setdefault('status', 'Open')
    return jsonify(complaints), 200

# === 🛠️ Update Complaint Status ===
@app.route('/api/complaints/<complaint_id>', methods=['PUT'])
def update_complaint_status(complaint_id):
    if 'username' not in session:
        return jsonify({'message': 'Please login first'}), 401
    user = users_collection.find_one({'username': session['username']})
    if not user or user.get('role') != 'admin':
        return jsonify({'message': 'Access denied'}), 403
    data = request.get_json()
    new_status = data.get('status')
    if not new_status:
        return jsonify({'message': 'Status is required'}), 400
    result = complaints_collection.update_one(
        {'_id': ObjectId(complaint_id)},
        {'$set': {'status': new_status, 'updated_by': session['username'], 'updated_at': datetime.now()}}
    )
    if result.matched_count:
        return jsonify({'message': 'Status updated successfully'}), 200
    return jsonify({'message': 'Complaint not found'}), 404

# === ❌ Delete Complaint ===
@app.route('/api/complaints/<complaint_id>', methods=['DELETE'])
def delete_complaint(complaint_id):
    if 'username' not in session:
        return jsonify({'message': 'Please login first'}), 401
    user = users_collection.find_one({'username': session['username']})
    complaint = complaints_collection.find_one({'_id': ObjectId(complaint_id)})
    if not complaint:
        return jsonify({'message': 'Complaint not found'}), 404
    if user.get('role') != 'admin' and complaint.get('username') != session['username']:
        return jsonify({'message': 'Unauthorized'}), 403
    complaints_collection.delete_one({'_id': ObjectId(complaint_id)})
    return jsonify({'message': 'Complaint deleted'}), 200

# === Static Pages ===
@app.route('/dashboard.html')
def protected_dashboard():
    if 'username' not in session or session.get('role') != 'student':
        return send_from_directory('.', 'index.html')
    return send_from_directory('.', 'dashboard.html')

@app.route('/warden.html')
def protected_warden():
    if 'username' not in session or session.get('role') != 'admin':
        return send_from_directory('.', 'index.html')
    return send_from_directory('.', 'warden.html')

@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory('.', filename)

# === 🚀 Run App ===
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5500))
    app.run(debug=True, host='0.0.0.0', port=port)
