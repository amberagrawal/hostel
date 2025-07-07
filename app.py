import os
import base64
from flask import Flask, request, jsonify, session, render_template, redirect, url_for
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from flask_mail import Mail, Message
from datetime import timedelta, datetime
from bson import ObjectId
import random
from werkzeug.utils import secure_filename
from flask import make_response

app = Flask(__name__)

CORS(app, supports_credentials=True)
# For production, restrict origins:
# CORS(app, origins=["https://your-frontend-url.onrender.com"], supports_credentials=True)

app.secret_key = os.environ.get('SECRET_KEY')
app.permanent_session_lifetime = timedelta(days=1)

app.config["MONGO_URI"] = os.environ.get("MONGO_URI")
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.environ.get("MAIL_PASSWORD")

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

mongo = PyMongo(app)
mail = Mail(app)
users_collection = mongo.db.user
complaints_collection = mongo.db.complaints
admin_id_collection = mongo.db.id
otp_collection = mongo.db.otp 

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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
        admin_id = str(admin_id).strip()
        result = admin_id_collection.find_one({'id': admin_id})
        if not result:
            return jsonify({'message': 'Admin ID not found'}), 403

    otp = str(random.randint(100000, 999999))
    # Remove any previous OTP for this user
    otp_collection.delete_many({'username': username})
    otp_collection.insert_one({
        'username': username,
        'otp': otp,
        'user': {
            'username': username,
            'password': generate_password_hash(password),
            'role': role,
            'email': email
        },
        'created_at': datetime.utcnow()
    })

    try:
        msg = Message('Your OTP Code', sender=app.config['MAIL_USERNAME'], recipients=[email])
        msg.body = f'Your OTP for registration is: {otp}'
        mail.send(msg)
    except Exception as e:
        print("Mail send failed:", e)
        return jsonify({'message': 'Failed to send OTP'}), 500

    return jsonify({'message': 'OTP sent to email'}), 200

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    username = data.get('username')
    entered_otp = data.get('otp')
    record = otp_collection.find_one({'username': username})

    if not record:
        return jsonify({'message': 'No OTP session found'}), 400

    # Check OTP expiry (10 minutes)
    expiry_time = record['created_at'] + timedelta(minutes=10)
    if datetime.utcnow() > expiry_time:
        otp_collection.delete_one({'_id': record['_id']})
        return jsonify({'message': 'OTP expired'}), 400

    if entered_otp == record['otp']:
        users_collection.insert_one(record['user'])
        otp_collection.delete_one({'_id': record['_id']})
        return jsonify({'message': 'Registration successful'}), 201
    else:
        return jsonify({'message': 'Invalid OTP'}), 403

@app.route('/login', methods=['POST'])
def login():
    try:
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
            redirect_url = url_for('dashboard') if session['role'] == 'student' else url_for('warden')
            return jsonify({'message': 'Login successful', 'redirect': redirect_url}), 200

        return jsonify({'message': 'Invalid credentials'}), 401
    except Exception as e:
        return jsonify({'message': 'Internal server error', 'error': str(e)}), 500


@app.route('/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    session.pop('role', None)
    return jsonify({'message': 'Logged out successfully'}), 200

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

    image_base64 = None
    if 'image' in request.files:
        file = request.files['image']
        if file and allowed_file(file.filename):
            image_data = file.read()
            image_base64 = base64.b64encode(image_data).decode('utf-8')

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
        'image_base64': image_base64  # <--- store image here
    }

    complaints_collection.insert_one(complaint)
    return jsonify({'message': 'Complaint submitted successfully'}), 200

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

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
    for complaint in complaints:
        complaint['_id'] = str(complaint['_id'])
        complaint.setdefault('status', 'Open')
    return jsonify(complaints), 200

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
    else:
        return jsonify({'message': 'Complaint not found'}), 404

@app.route('/api/complaints/<complaint_id>', methods=['DELETE'])
def delete_complaint(complaint_id):
    if 'username' not in session:
        return jsonify({'message': 'Please login first'}), 401
    user = users_collection.find_one({'username': session['username']})
    if not user:
        return jsonify({'message': 'User not found'}), 401
    complaint = complaints_collection.find_one({'_id': ObjectId(complaint_id)})
    if not complaint:
        return jsonify({'message': 'Complaint not found'}), 404
    if user.get('role') != 'admin' and complaint.get('username') != session['username']:
        return jsonify({'message': 'Unauthorized'}), 403
    complaints_collection.delete_one({'_id': ObjectId(complaint_id)})
    return jsonify({'message': 'Complaint deleted'}), 200

@app.route('/dashboard.html')
def dashboard():
    if 'username' not in session or session.get('role') != 'student':
        return render_template('index.html')
    response = make_response(render_template('dashboard.html'))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return response

@app.route('/warden.html')
def warden():
    if 'username' not in session or session.get('role') != 'admin':
        return render_template('index.html')
    response = make_response(render_template('warden.html'))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return response

@app.route('/')
def serve_index():
    return render_template('index.html')

@app.route('/<path:filename>')
def serve_static(filename):
    # Serve static files from the static folder
    return send_from_directory('static', filename)

if __name__ == '__main__':
    app.run(debug=True, port=5500)
