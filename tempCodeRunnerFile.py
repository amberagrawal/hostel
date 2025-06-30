from flask import Flask, request, jsonify, session, send_from_directory 
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from flask_mail import Mail, Message
from datetime import timedelta, datetime
from bson import ObjectId
import random

app = Flask(__name__)
CORS(app, origins=["http://127.0.0.1:5500"], supports_credentials=True)
app.secret_key = 'e7263a66b911619b7f3f427040384ec5'
app.permanent_session_lifetime = timedelta(days=1)

# MongoDB + Mail Config
app.config["MONGO_URI"] = "mongodb+srv://aagrawal009btech2023:6RMVVWoazfYm7XNa@cluster0.2zihrjq.mongodb.net/Mydatabase?retryWrites=true&w=majority&appName=Cluster0"
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'krishuagrawal692004@gmail.com'  # Your Gmail
app.config['MAIL_PASSWORD'] = 'cnez rtiq hllg crct'  # Gmail App Password

mongo = PyMongo(app)
mail = Mail(app)
users_collection = mongo.db.user
complaints_collection = mongo.db.complaints
otp_store = {}

# --- Registration with OTP ---
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'student')
    email = data.get('email')

    if users_collection.find_one({'username': username}):
        return jsonify({'message': 'User already exists'}), 409

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
    else:
        return jsonify({'message': 'Invalid OTP'}), 403

# --- Login with username and password only (email check optional) ---
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')  # Optional email from frontend

    user = users_collection.find_one({'username': username})
    if user and check_password_hash(user['password'], password):
        # Optional: Email match check
        if email and email.lower() != user.get('email', '').lower():
            return jsonify({'message': 'Email does not match'}), 401

        session['username'] = username
        session['role'] = user.get('role', 'student')
        redirect = '/dashboard.html' if session['role'] == 'student' else '/warden.html'
        return jsonify({'message': 'Login successful', 'role': session['role'], 'redirect': redirect}), 200

    return jsonify({'message': 'Invalid credentials'}), 401

# --- Logout ---
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    session.pop('role', None)
    return jsonify({'message': 'Logged out successfully'}), 200

# --- Submit Complaint (student only) ---
@app.route('/submit_complaint', methods=['POST'])
def submit_complaint():
    if 'username' not in session:
        return jsonify({'message': 'Please login first'}), 401
    data = request.get_json()
    required_fields = ['title', 'text', 'room', 'hostel', 'date']
    if not all(k in data for k in required_fields):
        return jsonify({'message': 'Missing data'}), 400
    data['username'] = session['username']
    data['email'] = users_collection.find_one({'username': session['username']})['email']
    data['status'] = 'Open'
    complaints_collection.insert_one(data)
    return jsonify({'message': 'Complaint submitted successfully'}), 200

# --- Get Complaints (student: own, admin: all) ---
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
        if 'status' not in complaint:
            complaint['status'] = 'Open'
    return jsonify(complaints), 200

# --- Update Complaint Status (admin only) ---
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

# --- Serve frontend files ---
@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory('.', filename)

if __name__ == '__main__':
    app.run(debug=True, port=5500)
