from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
import json
import uuid
from datetime import datetime, timedelta
import requests
import threading
import time
import re
import os
from openai import OpenAI
from dotenv import load_dotenv
from functools import wraps


load_dotenv()

app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)

ROOM_TIMEOUT = timedelta(hours=int(os.getenv('ROOM_TIMEOUT_HOURS', 24)))
CLEANUP_INTERVAL = int(os.getenv('CLEANUP_INTERVAL_SECONDS', 3600))

# Add this with other constants
MAX_ROOMS_PER_DEVICE = int(os.getenv('MAX_ROOMS_PER_DEVICE', 5))
ROOM_CREATION_WINDOW = timedelta(hours=24)
device_room_creation = {}

active_users = {}
chat_rooms = {}

ADMIN_SECRET_KEY = os.getenv('ADMIN_SECRET_KEY')

def cleanup_device_limits():
    """Background task to clean up old device limits"""
    while True:
        current_time = datetime.now()
        devices_to_delete = []
        
        for device_id, data in device_room_creation.items():
            if (current_time - data['last_reset']) > ROOM_CREATION_WINDOW:
                devices_to_delete.append(device_id)
        
        for device_id in devices_to_delete:
            del device_room_creation[device_id]
            print(f"Reset device limit for: {device_id}")
        
        time.sleep(3600)

# Start the cleanup thread
device_cleanup_thread = threading.Thread(target=cleanup_device_limits, daemon=True)
device_cleanup_thread.start()

def check_device_limit(device_id):
    """Check if device has exceeded room creation limit"""
    current_time = datetime.now()
    
    if device_id not in device_room_creation:
        device_room_creation[device_id] = {'count': 1, 'last_reset': current_time}
        return True
    
    # Reset counter if window has passed
    if (current_time - device_room_creation[device_id]['last_reset']) > ROOM_CREATION_WINDOW:
        device_room_creation[device_id] = {'count': 1, 'last_reset': current_time}
        return True
    
    if device_room_creation[device_id]['count'] >= MAX_ROOMS_PER_DEVICE:
        return False
    
    device_room_creation[device_id]['count'] += 1
    return True


def cleanup_inactive_rooms():
    """Background task to clean up inactive rooms"""
    while True:
        current_time = datetime.now()
        rooms_to_delete = []
        
        # Find rooms that haven't been active beyond the timeout period
        for room_id, room_data in chat_rooms.items():
            last_active = room_data.get('last_active')
            if last_active and (current_time - last_active) > ROOM_TIMEOUT:
                rooms_to_delete.append(room_id)
        
        # Delete inactive rooms
        for room_id in rooms_to_delete:
            del chat_rooms[room_id]
            print(f"Deleted inactive room: {room_id}")
        
        time.sleep(CLEANUP_INTERVAL)

# Start the cleanup thread
cleanup_thread = threading.Thread(target=cleanup_inactive_rooms, daemon=True)
cleanup_thread.start()


# Add this decorator for admin authentication
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Authorization header missing'}), 401
        
        token = auth_header.split(' ')[1]
        if token != ADMIN_SECRET_KEY:
            return jsonify({'error': 'Invalid admin token'}), 403
        
        return f(*args, **kwargs)
    return decorated_function

# Add these new routes to app.py
@app.route('/admin')
def admin_page():
    return render_template('admin.html')

@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    data = request.get_json()
    password = data.get('password')
    
    # Replace with your actual admin password check
    if password == os.getenv('ADMIN_PASSWORD'):  # Change this!
        return jsonify({'token': ADMIN_SECRET_KEY}), 200
    else:
        return jsonify({'error': 'Invalid password'}), 401

@app.route('/admin/dashboard')
def admin_dashboard():
    return render_template('admin_dashboard.html', MAX_ROOMS_PER_DEVICE=MAX_ROOMS_PER_DEVICE)

@app.route('/api/admin/rooms', methods=['GET', 'POST'])
@admin_required
def admin_rooms():
    if request.method == 'GET':
        rooms_info = []
        for room, info in chat_rooms.items():
            rooms_info.append({
                'name': room,
                'protected': bool(info.get('password_hash')),
                'user_count': len(info.get('users', [])),
                'message_count': len(info.get('messages', []))
            })
        return jsonify({'rooms': rooms_info})
    
    elif request.method == 'POST':
        data = request.get_json()
        room_name = data.get('name')
        password = data.get('password')
        force_create = data.get('force', False)  # New flag to bypass limits
        
        if not room_name:
            return jsonify({'error': 'Room name required'}), 400
        
        if room_name in chat_rooms:
            return jsonify({'error': 'Room already exists'}), 400
        
        # Get client IP
        # Use 'admin' as device ID for admin requests
        device_id = 'admin'

        # Check device limit unless forcing
        if not force_create and not check_device_limit(device_id):
            return jsonify({
                'error': f'Device limit reached ({MAX_ROOMS_PER_DEVICE} rooms/day). Use force=true to override.',
                'limit_reached': True
            }), 429
        
        chat_rooms[room_name] = {
            'users': set(),
            'messages': [],
            'password_hash': generate_password_hash(password) if password else None,
            'last_active': datetime.now()
        }
        
        return jsonify({
            'status': 'room created', 
            'room': room_name,
            'remaining': MAX_ROOMS_PER_DEVICE - device_room_creation.get(device_id, {}).get('count', 0)
        }), 201

@app.route('/api/admin/rooms/<room_name>', methods=['DELETE'])
@admin_required
def admin_delete_room(room_name):
    if room_name not in chat_rooms:
        return jsonify({'error': 'Room not found'}), 404
    
    # Notify users in the room that it's being deleted
    for sid in chat_rooms[room_name]['users']:
        socketio.emit('room_deleted', {
            'room': room_name,
            'message': 'This room has been deleted by admin'
        }, room=sid)
    
    del chat_rooms[room_name]
    return jsonify({'status': 'room deleted'}), 200

@app.route('/api/admin/stats')
@admin_required
def admin_stats():
    """Get global statistics for the admin dashboard"""
    
    # Calculate total rooms
    total_rooms = len(chat_rooms)
    
    # Calculate active users (users currently connected to any room)
    active_users_count = len(active_users)
    
    # Calculate messages today (messages sent in the last 24 hours)
    messages_today = 0
    current_time = datetime.now()
    
    for room_name, room_data in chat_rooms.items():
        for message in room_data.get('messages', []):
            # Parse timestamp if it's a string, or use directly if it's a datetime object
            if isinstance(message.get('timestamp'), str):
                message_time = datetime.fromisoformat(message['timestamp'])
            else:
                message_time = message.get('timestamp', current_time)
            
            if (current_time - message_time) < timedelta(hours=24):
                messages_today += 1
    
    # Calculate protected rooms
    protected_rooms = 0
    for room_name, room_data in chat_rooms.items():
        if room_data.get('password_hash'):
            protected_rooms += 1
    
    return jsonify({
        'total_rooms': total_rooms,
        'active_users': active_users_count,
        'total_messages': messages_today,
        'protected_rooms': protected_rooms
    })

@app.route('/')
def index():
    return render_template('landing.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/room/<room_id>')
def room_page(room_id):
    room_info = chat_rooms.get(room_id)
    if not room_info:
        return redirect(url_for('index'))

    # Check if room is protected and user doesn't have access
    if room_info.get('password_hash') and not session.get(f'room_access_{room_id}'):
        # Redirect to password page instead of rendering it directly
        return redirect(url_for('room_password', room=room_id))

    chat_rooms[room_id]['last_active'] = datetime.now()

    return render_template('index.html', room_id=room_id)

# Add this route to handle the password page
@app.route('/room_password')
def room_password():
    room_id = request.args.get('room')
    if not room_id or room_id not in chat_rooms:
        return redirect(url_for('index'))
    
    return render_template('room_password.html', room_id=room_id)

@app.route('/api/rooms/check')
def check_room():
    room_name = request.args.get('name')
    if not room_name:
        return jsonify({'error': 'Room name required'}), 400
    
    exists = room_name in chat_rooms
    return jsonify({'exists': exists})

@app.route('/create_room', methods=['POST'])
def create_room():
    # Get client IP (handles proxies)
    data = request.get_json()
    device_id = data.get('device_id', 'unknown')
    
    # 🎯 ADD DEBUG LOGGING
    print(f"=== CREATE ROOM DEBUG ===")
    print(f"Device ID received: {device_id}")
    print(f"Client IP: {request.remote_addr}")
    print(f"All device limits: {device_room_creation}")
    print(f"========================")

    # Check device limit
    if not check_device_limit(device_id):
        return jsonify({
            'error': f'You can only create {MAX_ROOMS_PER_DEVICE} rooms per day per device. Try again later.'
        }), 429
    
    room_name = data.get('room', '').strip()
    password = data.get('password')

    # Rest of the existing validation...
    if not (3 <= len(room_name) <= 15):
        return jsonify({'error': 'Room name must be 3-15 characters'}), 400
    if not re.match(r'^[a-z0-9]+$', room_name, re.IGNORECASE):
        return jsonify({'error': 'Only letters and numbers allowed'}), 400
    if room_name in chat_rooms:
        return jsonify({'error': 'Room already exists'}), 409

    # Create room
    chat_rooms[room_name] = {
        'users': set(),
        'messages': [],
        'password_hash': generate_password_hash(password) if password else None,
        'last_active': datetime.now()
    }
    
    return jsonify({
        'status': 'Room created',
        'remaining': MAX_ROOMS_PER_DEVICE - device_room_creation[device_id]['count'],
        'reset_time': (device_room_creation[device_id]['last_reset'] + ROOM_CREATION_WINDOW).isoformat()
    }), 201

 
@app.route('/api/rooms')
def api_rooms():
    rooms_info = []
    for room, info in chat_rooms.items():
        rooms_info.append({
            'name': room,
            'protected': bool(info.get('password_hash')),
            'last_active': info.get('last_active', datetime.now()).isoformat()
        })
    return jsonify({'rooms': rooms_info})

 
@app.route('/verify_room', methods=['POST'])
def verify_room():
    data = request.get_json() or {}
    room = data.get('room')
    password = data.get('password')

    if not room or room not in chat_rooms:
        return jsonify({'ok': False, 'error': 'Room not found'}), 404

    stored_hash = chat_rooms[room].get('password_hash')
    if stored_hash is None:
        session[f'room_access_{room}'] = True
        return jsonify({'ok': True})

    if password and check_password_hash(stored_hash, password):
        session[f'room_access_{room}'] = True
        return jsonify({'ok': True})

    return jsonify({'ok': False, 'error': 'Invalid password'}), 403

@app.route("/ai_summarize", methods=["POST"])
def ai_summarize():
    # Validate request
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.get_json()
    code = data.get("code", "").strip()
    
    if not code:
        return jsonify({"error": "No code provided"}), 400

    # Validate code length (prevent abuse)
    if len(code) > 10000:
        return jsonify({"error": "Code too long (max 10,000 characters)"}), 400

    # Prepare the prompt
    prompt = f"""
    You are an AI assistant. Summarize the given code in exactly 2 sentences.

    code:
    ```{code}```

    Instructions:
    1. Detect the programming language automatically.
    2. First sentence: briefly describe what the code is trying to do.
    3. Second sentence: explain the actual runtime behavior (successful output or the exact error and why).
    4. Output must strictly follow this format:

    Language: <Detected Language>
    Summary: <two-sentence summary>
    """
        
    ########## Get API key from environment - Groq
    try:
        client = OpenAI(
            api_key=os.environ.get("GROQ_API_KEY"),
            base_url="https://api.groq.com/openai/v1",
        )
        response = client.responses.create(
            model="llama-3.1-8b-instant",
            input = prompt,
            max_output_tokens=200
        )

        summary = response.output_text
        
        return jsonify({"summary": response.output_text})
    
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Groq API request failed: {str(e)}")
        return jsonify({"error": f"AI service unavailable: {str(e)}"}), 503
    except KeyError as e:
        app.logger.error(f"Malformed API response: {str(e)}")
        return jsonify({"error": "AI service returned malformed response"}), 502
    except Exception as e:
        if hasattr(e, "status_code") and e.status_code == 429:
            app.logger.error(f"Unexpected error: {str(e)}")
            return jsonify({"summary": "⚠️ AI is busy (rate limit hit). Please try again in a few seconds."})
        else:
            app.logger.error(f"Unexpected error: {str(e)}")
            return jsonify({"summary": f"❌ Error: {str(e)}"})


@socketio.on('connect')
def handle_connect():
    print(f'Client connected: {request.sid}')
    emit('connected', {'status': 'connected'})

@socketio.on('disconnect')
def handle_disconnect():
    if request.sid in active_users:
        user_info = active_users[request.sid]
        room = user_info.get('room')
        if room and room in chat_rooms:
            emit('user_left', {
                'user_name': user_info['user_name']
            }, room=room)
            leave_room(room)
            chat_rooms[room]['users'].discard(request.sid)
        del active_users[request.sid]


@socketio.on('join_chat')
def handle_join_chat(data):
    user_id = str(uuid.uuid4())[:8]   
    room = data.get('room', 'general')
    user_name = data.get('name', f'User {user_id}')
    
    # Create room if it doesn't exist
    if room not in chat_rooms:
        chat_rooms[room] = {
            'users': set(),
            'messages': [],
            'password_hash': None,
            'last_active': datetime.now()
        }
    
    # Update last active time when someone joins
    chat_rooms[room]['last_active'] = datetime.now()
    
    # Rest of the join_chat handler remains the same
    join_room(room)
    chat_rooms[room]['users'].add(request.sid)
    
    active_users[request.sid] = {
        'user_id': user_id,
        'user_name': user_name,
        'room': room,
        'joined_at': datetime.now().isoformat()
    }
    
    welcome_msg = {
        'id': str(uuid.uuid4()),
        'type': 'system',
        'content': f'{user_name} joined the chat',
        'timestamp': datetime.now().isoformat(),
        'user_id': 'system'
    }
    
    emit('user_joined', {
        'user_id': user_id,
        'user_name': user_name,
        'message': welcome_msg
    }, room=room)
    
    emit('chat_history', {
        'messages': chat_rooms[room]['messages'][-50:]   
    })

@socketio.on('send_message')
def handle_send_message(data):
    if request.sid not in active_users:
        return
    
    user_info = active_users[request.sid]
    room = user_info['room']
    user_id = user_info['user_id']
    user_name = user_info['user_name']
    
    message_data = {
        'id': str(uuid.uuid4()),
        'type': 'user',
        'content': data['message'],
        'timestamp': datetime.now().isoformat(),
        'user_id': user_id,
        'user_name': user_name,
        'is_code': data.get('is_code', False)
    }
    
     
    chat_rooms[room]['messages'].append(message_data)
    
     
    if len(chat_rooms[room]['messages']) > 100:
        chat_rooms[room]['messages'] = chat_rooms[room]['messages'][-100:]
    
     
    emit('new_message', message_data, room=room, include_self=False)
    
     
    emit('message_sent', {
        'id': message_data['id'],
        'status': 'sent'
    })

@socketio.on('typing')
def handle_typing(data):
    if request.sid not in active_users:
        return
    
    user_info = active_users[request.sid]
    room = user_info['room']
    user_id = user_info['user_id']
    user_name = user_info['user_name']
    
    # Handle both boolean and dictionary formats
    if isinstance(data, bool):
        is_typing = data
    else:
        is_typing = data.get('is_typing', False)
    
    emit('user_typing', {
        'user_id': user_id,
        'user_name': user_name,
        'is_typing': is_typing
    }, room=room, include_self=False)

if __name__ == '__main__':
    print("Starting Anonymous Chat Server...")
    print("Visit http://localhost:8070 to join the chat!")
    socketio.run(app, debug=True, host='0.0.0.0', port=8070)