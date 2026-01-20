from flask import Flask, request, render_template, redirect, url_for, session, flash, make_response
import tensorflow as tf
import numpy as np
import cv2
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
from datetime import datetime, timedelta
from functools import wraps


app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg'}
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  
app.config['SECRET_KEY'] = 'your_secret_key_change_in_production_12345'

# Session configuration - CRITICAL
app.config['SESSION_COOKIE_NAME'] = 'signature_session'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_REFRESH_EACH_REQUEST'] = False

ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'admin'

db_config = { 
    'host': 'localhost',
    'user': 'root',
    'password': 'root',
    'database': 'handdbnew'
}

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def get_db_connection():
    conn = mysql.connector.connect(**db_config)
    return conn

try:
    conn = get_db_connection()
    conn.close()
    print("✓ Connected to MySQL")
except Exception as e:
    print(f"✗ Error connecting to MySQL: {e}")

try:
    model = tf.keras.models.load_model('best_model.kernel', compile=False)
    print("✓ Model loaded successfully")
except Exception as e:
    print(f"✗ Error loading model: {e}")
    model = None

# Helper function to check if user is actually logged in
def is_user_logged_in():
    return 'username' in session and 'user_id' in session and session.get('logged_in') == True

# Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_user_logged_in():
            session.clear()
            flash('Please login to access this page', 'warning')
            response = make_response(redirect(url_for('login')))
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
            return response
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session or not session.get('admin_logged_in'):
            session.clear()
            flash('Admin access required', 'danger')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def preprocess_image(img_path):
    try:
        img = tf.io.read_file(img_path)
        img = tf.image.decode_png(img, channels=1)
        img = tf.image.resize(img, (128, 128))
        img = tf.cast(img, tf.uint8)
        img_cv2 = cv2.Canny(img.numpy(), 20, 220)
        img_cv2 = tf.cast(img_cv2, tf.float32) / 255.0
        return np.expand_dims(img_cv2, axis=-1)
    except Exception as e:
        print(f"Error preprocessing image: {e}")
        return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/graph')
@login_required
def graph():
    return render_template('graph.html')

# COMPLETELY REWRITTEN SIGNUP ROUTE
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    # Don't redirect if already logged in - just clear and show signup
    if request.method == 'GET':
        # Clear session completely when accessing signup page
        session.clear()
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        if not username or not email or not password:
            flash('All fields are required', 'danger')
            return redirect(url_for('signup'))
        
        if len(username) < 3:
            flash('Username must be at least 3 characters long', 'danger')
            return redirect(url_for('signup'))
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long', 'danger')
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('SELECT * FROM users WHERE email = %s OR username = %s', (email, username))
            existing_user = cursor.fetchone()
            
            if existing_user:
                flash('Email or username already exists. Please try another.', 'warning')
            else:
                cursor.execute(
                    'INSERT INTO users (username, email, password, created_at) VALUES (%s, %s, %s, NOW())', 
                    (username, email, hashed_password)
                )
                conn.commit()
                flash('Signup successful! Please login.', 'success')
                cursor.close()
                conn.close()
                return redirect(url_for('login'))
        except mysql.connector.Error as err:
            flash(f'Error: {err}', 'danger')
        finally:
            cursor.close()
            conn.close()

        return redirect(url_for('signup'))

    # Render with no-cache headers
    response = make_response(render_template('signup.html'))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# COMPLETELY REWRITTEN LOGIN ROUTE
@app.route('/login', methods=['GET', 'POST'])
def login():
    # On GET request, ALWAYS clear session first
    if request.method == 'GET':
        # Store flash messages before clearing
        flashed_messages = list(session.get('_flashes', []))
        
        # Complete session clear
        session.clear()
        
        # Restore flash messages
        if flashed_messages:
            session['_flashes'] = flashed_messages
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash('Username and password are required', 'danger')
            return redirect(url_for('login'))

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
            user = cursor.fetchone()
            cursor.close()
            conn.close()

            if user and check_password_hash(user[3], password):
                # Check if user is active
                if not user[6]:  # is_active column
                    flash('Your account has been deactivated. Contact administrator.', 'danger')
                    return redirect(url_for('login'))
                
                # COMPLETE session reset
                session.clear()
                
                # Set new session data with logged_in flag
                session['username'] = username
                session['user_id'] = user[0]
                session['logged_in'] = True
                session.permanent = True
                session.modified = True
                
                # Update last login
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute('UPDATE users SET last_login = NOW() WHERE username = %s', (username,))
                conn.commit()
                cursor.close()
                conn.close()
                
                flash('Login successful!', 'success')
                return redirect(url_for('predict'))
            else:
                flash('Invalid username or password', 'danger')
                return redirect(url_for('login'))
        except mysql.connector.Error as err:
            flash(f'Database error: {err}', 'danger')
            return redirect(url_for('login'))

    # Render login page with no-cache headers
    response = make_response(render_template('login.html'))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# COMPLETELY REWRITTEN LOGOUT ROUTE
@app.route('/logout')
def logout():
    username = session.get('username', 'User')
    
    # Nuclear option - destroy everything
    session.clear()
    session.modified = True
    
    # Create response
    flash(f'Goodbye {username}! You have been logged out successfully.', 'success')
    response = make_response(redirect(url_for('login')))
    
    # Delete cookies
    response.set_cookie('signature_session', '', expires=0)
    response.set_cookie('session', '', expires=0)
    
    # Aggressive headers
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.headers['Clear-Site-Data'] = '"cache", "cookies", "storage"'
    
    return response

@app.route('/predict', methods=['GET', 'POST'])
@login_required
def predict():
    if model is None:
        flash('Model not loaded. Please contact administrator.', 'danger')
        return render_template('predict.html', result=None)
    
    if request.method == 'POST':
        if 'image1' not in request.files or 'image2' not in request.files:
            flash('Both signature images are required', 'danger')
            return redirect(request.url)
        
        file1 = request.files['image1']
        file2 = request.files['image2']
        
        if file1.filename == '' or file2.filename == '':
            flash('Please select both images', 'danger')
            return redirect(request.url)
        
        if file1 and allowed_file(file1.filename) and file2 and allowed_file(file2.filename):
            try:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename1 = f"{session['username']}_{timestamp}_1_{secure_filename(file1.filename)}"
                filename2 = f"{session['username']}_{timestamp}_2_{secure_filename(file2.filename)}"
                
                filepath1 = os.path.join(app.config['UPLOAD_FOLDER'], filename1)
                filepath2 = os.path.join(app.config['UPLOAD_FOLDER'], filename2)
                file1.save(filepath1)
                file2.save(filepath2)

                img1 = preprocess_image(filepath1)
                img2 = preprocess_image(filepath2)
                
                if img1 is None or img2 is None:
                    flash('Error processing images. Please try again.', 'danger')
                    return redirect(request.url)

                prediction = model.predict([np.expand_dims(img1, axis=0), np.expand_dims(img2, axis=0)])
                matched_percentage = (1 - prediction[0][0]) * 100
                matched_percentage_float = float(matched_percentage)
                matched_percentage_str = f"{matched_percentage:.2f}"
                result = 'Real' if prediction[0][0] < 0.5 else 'Fake'
                sign = "Matched" if result == "Real" else "Not Matched"

                db_path1 = os.path.join('uploads', filename1).replace('\\', '/')
                db_path2 = os.path.join('uploads', filename2).replace('\\', '/')

                try:
                    conn = get_db_connection()
                    cursor = conn.cursor()
                    cursor.execute(
                        '''INSERT INTO predictions_history 
                           (username, image1_path, image2_path, result, matched_percentage, prediction_date) 
                           VALUES (%s, %s, %s, %s, %s, NOW())''',
                        (session['username'], db_path1, db_path2, result, matched_percentage_float)
                    )
                    conn.commit()
                    cursor.close()
                    conn.close()
                except mysql.connector.Error as err:
                    flash(f'Error saving history: {err}', 'danger')

                gif_url = url_for('static', filename='real.gif' if result == 'Real' else 'fake.gif')

                return render_template('predict.html', result=result, img1_url=filepath1, 
                                     img2_url=filepath2, gif_url=gif_url, sign=sign, 
                                     matched_percentage=matched_percentage_str)
            except Exception as e:
                flash(f'Error processing prediction: {str(e)}', 'danger')
                return redirect(request.url)
        else:
            flash('Invalid file format. Only PNG, JPG, and JPEG are allowed.', 'danger')
    
    return render_template('predict.html', result=None)

@app.route('/history')
@login_required
def history():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    if page < 1:
        page = 1
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute(
            'SELECT COUNT(*) as total FROM predictions_history WHERE username = %s',
            (session['username'],)
        )
        total_records = cursor.fetchone()['total']
        
        total_pages = max(1, (total_records + per_page - 1) // per_page)
        
        if page > total_pages and total_records > 0:
            page = total_pages
        
        offset = (page - 1) * per_page
        
        cursor.execute(
            '''SELECT id, image1_path, image2_path, result, matched_percentage, 
                      prediction_date 
               FROM predictions_history 
               WHERE username = %s 
               ORDER BY prediction_date DESC 
               LIMIT %s OFFSET %s''',
            (session['username'], per_page, offset)
        )
        history_records = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return render_template('history.html', 
                             history=history_records, 
                             page=page, 
                             total_pages=total_pages,
                             total_records=total_records)
    
    except mysql.connector.Error as err:
        flash(f'Error loading history: {err}', 'danger')
        return redirect(url_for('predict'))

@app.route('/delete_history/<int:id>')
@login_required
def delete_history(id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            'SELECT image1_path, image2_path FROM predictions_history WHERE id = %s AND username = %s',
            (id, session['username'])
        )
        record = cursor.fetchone()
        
        if record:
            cursor.execute(
                'DELETE FROM predictions_history WHERE id = %s AND username = %s',
                (id, session['username'])
            )
            conn.commit()
            
            try:
                img1_full_path = os.path.join('static', record[0])
                img2_full_path = os.path.join('static', record[1])
                
                if os.path.exists(img1_full_path):
                    os.remove(img1_full_path)
                if os.path.exists(img2_full_path):
                    os.remove(img2_full_path)
            except OSError as e:
                print(f"Error deleting files: {e}")
            
            flash('History record deleted successfully', 'success')
        else:
            flash('Record not found or unauthorized', 'danger')
        
        cursor.close()
        conn.close()
        
    except mysql.connector.Error as err:
        flash(f'Error deleting record: {err}', 'danger')
    
    return redirect(url_for('history'))

# ========== ADMIN ROUTES ==========

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if session.get('admin_logged_in'):
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'GET':
        session.clear()
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session.clear()
            session['admin_logged_in'] = True
            session['admin_username'] = username
            session.permanent = True
            flash('Admin login successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials', 'danger')
    
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.clear()
    flash('Admin logged out successfully', 'success')
    response = make_response(redirect(url_for('admin_login')))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute('SELECT COUNT(*) as total FROM users')
        total_users = cursor.fetchone()['total']
        
        cursor.execute('SELECT COUNT(*) as total FROM predictions_history')
        total_predictions = cursor.fetchone()['total']
        
        cursor.execute('SELECT result, COUNT(*) as count FROM predictions_history GROUP BY result')
        result_counts = cursor.fetchall()
        real_count = sum(r['count'] for r in result_counts if r['result'] == 'Real')
        fake_count = sum(r['count'] for r in result_counts if r['result'] == 'Fake')
        
        cursor.execute('SELECT AVG(matched_percentage) as avg_match FROM predictions_history')
        avg_match = cursor.fetchone()['avg_match'] or 0
        
        cursor.execute('''
            SELECT id, username, email, created_at, last_login, is_active 
            FROM users 
            ORDER BY created_at DESC 
            LIMIT 10
        ''')
        recent_users = cursor.fetchall()
        
        cursor.execute('''
            SELECT p.id, p.username, p.result, p.matched_percentage, p.prediction_date 
            FROM predictions_history p
            ORDER BY p.prediction_date DESC 
            LIMIT 10
        ''')
        recent_predictions = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return render_template('admin_dashboard.html',
                             total_users=total_users,
                             total_predictions=total_predictions,
                             real_count=real_count,
                             fake_count=fake_count,
                             avg_match=round(avg_match, 2),
                             recent_users=recent_users,
                             recent_predictions=recent_predictions)
    
    except mysql.connector.Error as err:
        flash(f'Error loading dashboard: {err}', 'danger')
        return redirect(url_for('admin_login'))

@app.route('/admin/users')
@admin_required
def admin_users():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute('''
            SELECT u.id, u.username, u.email, u.created_at, u.last_login, u.is_active,
                   COUNT(p.id) as prediction_count
            FROM users u
            LEFT JOIN predictions_history p ON u.username = p.username
            GROUP BY u.id
            ORDER BY u.created_at DESC
        ''')
        users = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return render_template('admin_users.html', users=users)
    
    except mysql.connector.Error as err:
        flash(f'Error loading users: {err}', 'danger')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/user/<int:user_id>')
@admin_required
def admin_user_detail(user_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
        user = cursor.fetchone()
        
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('admin_users'))
        
        cursor.execute('''
            SELECT id, image1_path, image2_path, result, matched_percentage, prediction_date
            FROM predictions_history
            WHERE username = %s
            ORDER BY prediction_date DESC
        ''', (user['username'],))
        predictions = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return render_template('admin_user_detail.html', user=user, predictions=predictions)
    
    except mysql.connector.Error as err:
        flash(f'Error loading user details: {err}', 'danger')
        return redirect(url_for('admin_users'))

@app.route('/admin/user/<int:user_id>/toggle_status')
@admin_required
def admin_toggle_user_status(user_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('UPDATE users SET is_active = NOT is_active WHERE id = %s', (user_id,))
        conn.commit()
        
        cursor.close()
        conn.close()
        
        flash('User status updated successfully', 'success')
    except mysql.connector.Error as err:
        flash(f'Error updating user status: {err}', 'danger')
    
    return redirect(url_for('admin_users'))

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM users WHERE id = %s', (user_id,))
        conn.commit()
        
        cursor.close()
        conn.close()
        
        flash('User deleted successfully', 'success')
    except mysql.connector.Error as err:
        flash(f'Error deleting user: {err}', 'danger')
    
    return redirect(url_for('admin_users'))

@app.route('/admin/predictions')
@admin_required
def admin_predictions():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute('SELECT COUNT(*) as total FROM predictions_history')
        total_records = cursor.fetchone()['total']
        
        total_pages = max(1, (total_records + per_page - 1) // per_page)
        offset = (page - 1) * per_page
        
        cursor.execute('''
            SELECT id, username, image1_path, image2_path, result, matched_percentage, prediction_date
            FROM predictions_history
            ORDER BY prediction_date DESC
            LIMIT %s OFFSET %s
        ''', (per_page, offset))
        predictions = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return render_template('admin_predictions.html',
                             predictions=predictions,
                             page=page,
                             total_pages=total_pages,
                             total_records=total_records)
    
    except mysql.connector.Error as err:
        flash(f'Error loading predictions: {err}', 'danger')
        return redirect(url_for('admin_dashboard'))

# Critical: Prevent caching on ALL routes
@app.after_request
def add_no_cache_headers(response):
    # Add no-cache headers to ALL responses
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

@app.errorhandler(413)
def file_too_large(e):
    flash('File size exceeds 5MB limit', 'danger')
    return redirect(url_for('predict'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)
