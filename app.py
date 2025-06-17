from flask import Flask, render_template, request, redirect, session, url_for
from flask_socketio import SocketIO, emit, join_room, leave_room
from crypto_utils import generate_rsa_keys, encrypt_message, decrypt_message
import sqlite3
import os
from datetime import datetime
from functools import wraps
from filters import datetimeformat

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)
app.jinja_env.filters['datetimeformat'] = datetimeformat
socketio = SocketIO(app, cors_allowed_origins="*", logger=True, engineio_logger=True)

# Database and user management
class Database:
    def __init__(self):
        self.conn = None
        self.init_db()
    
    def init_db(self):
        with self.get_connection() as conn:
            c = conn.cursor()
            
            # Users table
            c.execute('''CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                public_key TEXT NOT NULL,
                private_key TEXT NOT NULL,
                last_seen TEXT,
                avatar_color TEXT,
                online BOOLEAN DEFAULT FALSE
            )''')
            
            # Messages table
            c.execute('''CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL,
                receiver TEXT NOT NULL,
                content TEXT NOT NULL,
                content_sender TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(sender) REFERENCES users(username),
                FOREIGN KEY(receiver) REFERENCES users(username)
            )''')
            
            # Indexes
            c.execute('''CREATE INDEX IF NOT EXISTS idx_messages_sender_receiver 
                         ON messages(sender, receiver)''')
            c.execute('''CREATE INDEX IF NOT EXISTS idx_messages_timestamp 
                         ON messages(timestamp)''')
            
            conn.commit()
    
    def get_connection(self):
        if self.conn is None:
            self.conn = sqlite3.connect('database.db', check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
        return self.conn
    
    def close(self):
        if self.conn:
            self.conn.close()
            self.conn = None

db = Database()

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function 

def generate_avatar_color(username):
    colors = [
        'bg-purple-500', 'bg-blue-500', 'bg-green-500', 
        'bg-red-500', 'bg-yellow-500', 'bg-pink-500', 
        'bg-indigo-500', 'bg-teal-500', 'bg-orange-500'
    ]
    return colors[hash(username) % len(colors)]

def update_user_status(username, online):
    with db.get_connection() as conn:
        conn.execute(
            "UPDATE users SET online = ?, last_seen = datetime('now') WHERE username = ?",
            (online, username)
        )
        conn.commit()

# Routes
@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('chat'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            return render_template('register.html', error='Username and password are required')
        
        if len(username) < 3 or len(password) < 6:
            return render_template('register.html', 
                                error='Username must be at least 3 characters and password 6 characters')
        
        keys = generate_rsa_keys()
        avatar_color = generate_avatar_color(username)

        try:
            with db.get_connection() as conn:
                conn.execute(
                    "INSERT INTO users (username, password, public_key, private_key, avatar_color) VALUES (?, ?, ?, ?, ?)",
                    (username, password, keys['public'], keys['private'], avatar_color)
                )
                conn.commit()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return render_template('register.html', error='Username already taken')
        except Exception as e:
            return render_template('register.html', error=f'Registration error: {str(e)}')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        with db.get_connection() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE username = ?", 
                (username,)
            ).fetchone()

        if user and user['password'] == password:
            session['username'] = username
            update_user_status(username, True)
            return redirect(url_for('chat'))
        return render_template('login.html', error='Invalid username or password')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    username = session.pop('username', None)
    if username:
        update_user_status(username, False)
        socketio.emit('user_disconnected', {'username': username})

        socketio.emit('user_disconnected', 
                     {'username': username},
                     namespace='/')
    return redirect(url_for('index'))

@app.route('/chat')
@login_required
def chat():
    username = session['username']
    
    with db.get_connection() as conn:
        # Get current user info
        current_user = conn.execute(
            "SELECT username, avatar_color FROM users WHERE username = ?",
            (username,)
        ).fetchone()
        
        # Get all other users with their last message and online status
        users = conn.execute('''
            SELECT 
                u.username, 
                u.avatar_color,
                u.online,
                (SELECT m.content_sender 
                 FROM messages m 
                 WHERE (m.sender = u.username AND m.receiver = ?) 
                    OR (m.sender = ? AND m.receiver = u.username)
                 ORDER BY m.timestamp DESC 
                 LIMIT 1) as last_message,
                (SELECT m.timestamp 
                 FROM messages m 
                 WHERE (m.sender = u.username AND m.receiver = ?) 
                    OR (m.sender = ? AND m.receiver = u.username)
                 ORDER BY m.timestamp DESC 
                 LIMIT 1) as last_message_time
            FROM users u
            WHERE u.username != ?
            ORDER BY u.online DESC, last_message_time DESC NULLS LAST, u.username
        ''', (username, username, username, username, username)).fetchall()
    
    return render_template('chat.html', 
                         users=users, 
                         current_user=current_user['username'],
                         current_user_color=current_user['avatar_color'])

# Socket.IO Events
@socketio.on('connect')
def handle_connect():
    if 'username' in session:
        username = session['username']
        join_room(username)
        update_user_status(username, True)
        emit('user_connected', {'username': username}, broadcast=True)
        emit('connection_ack', {'status': 'connected'})

@socketio.on('disconnect')
def handle_disconnect():
    if 'username' in session:
        username = session['username']
        leave_room(username)
        update_user_status(username, False)
        emit('user_disconnected', {'username': username}, broadcast=True)

@socketio.on('get_online_users')
def handle_get_online_users():
    with db.get_connection() as conn:
        online_users = conn.execute(
            "SELECT username FROM users WHERE online = TRUE"
        ).fetchall()
        emit('online_users_list', [user['username'] for user in online_users])

@socketio.on('send_message')
def handle_send_message(data):
    sender = session.get('username')
    if not sender:
        return {'success': False, 'error': 'Not authenticated'}
    
    receiver = data.get('receiver')
    message = data.get('message', '').strip()
    
    if not receiver or not message:
        return {'success': False, 'error': 'Invalid message data'}
    
    try:
        with db.get_connection() as conn:
            # Get receiver's public key
            receiver_key = conn.execute(
                "SELECT public_key FROM users WHERE username = ?", 
                (receiver,)
            ).fetchone()
            
            if not receiver_key:
                return {'success': False, 'error': 'Receiver not found'}
            
            # Use crypto_utils for encryption
            encoded_msg = encrypt_message(receiver_key['public_key'], message)
            if not encoded_msg:
                return {'success': False, 'error': 'Encryption failed'}
            
            conn.execute('''
                INSERT INTO messages (sender, receiver, content, content_sender)
                VALUES (?, ?, ?, ?)
            ''', (sender, receiver, encoded_msg, message))
            conn.commit()

            msg_data = {
                'sender': sender,
                'receiver': receiver,
                'message': message,
                'timestamp': datetime.now().isoformat(),
                'isCurrentUser': False
            }

            emit('receive_message', msg_data, room=receiver)
            msg_data['isCurrentUser'] = True
            emit('receive_message', msg_data, room=sender)
            
            return {'success': True}
    except Exception as e:
        return {'success': False, 'error': str(e)}

@socketio.on('load_messages')
def handle_load_messages(data):
    contact = data.get('contact')
    username = session.get('username')
    
    if not contact or not username:
        return
    
    try:
        with db.get_connection() as conn:
            private_key = conn.execute(
                "SELECT private_key FROM users WHERE username = ?", 
                (username,)
            ).fetchone()
            
            if not private_key:
                return
            
            messages = conn.execute('''
                SELECT sender, content, content_sender, timestamp 
                FROM messages 
                WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)
                ORDER BY timestamp
            ''', (username, contact, contact, username)).fetchall()
            
            result = []
            for msg in messages:
                if msg['sender'] == username:
                    decrypted = msg['content_sender']
                else:
                    decrypted = decrypt_message(private_key['private_key'], msg['content'])
                
                result.append({
                    'sender': msg['sender'],
                    'message': decrypted,
                    'timestamp': msg['timestamp'],
                    'isCurrentUser': msg['sender'] == username
                })
            
            emit('chat_history', result)
    except Exception as e:
        print(f"Error loading messages: {e}")

if __name__ == '__main__':
    try:
        socketio.run(app, debug=True, host='0.0.0.0', port=5000)
    finally:
        db.close()