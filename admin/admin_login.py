from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from functools import wraps
import pymysql
from werkzeug.security import check_password_hash

# Blueprint for admin login routes
admin_login_bp = Blueprint('admin_login', __name__, template_folder='templates')

# Static admin fallback credentials (avoid using in production)
STATIC_ADMIN_USERNAME = "Che Blaise"
STATIC_ADMIN_PASSWORD = "1234567890"

# Database connection function
def get_db_connection():
    return pymysql.connect(
        host='localhost',
        user='root',
        password='',
        database='phishing_db'
    )

# Admin login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('admin_login.admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# Admin login route
@admin_login_bp.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        print(f"[DEBUG] Attempting login with username: {username}")

        # Static admin credentials check
        if username == STATIC_ADMIN_USERNAME and password == STATIC_ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            session['username'] = username
            flash('Login successful (static credentials).', 'success')
            print("[DEBUG] Static login success")
            return redirect(url_for('admin_dashboard'))

        # Check admin in DB
        try:
            conn = get_db_connection()
            cursor = conn.cursor(pymysql.cursors.DictCursor)
            cursor.execute("SELECT password FROM admins WHERE username = %s", (username,))
            result = cursor.fetchone()
            cursor.close()
            conn.close()

            if result and check_password_hash(result['password'], password):
                session['admin_logged_in'] = True
                session['username'] = username
                flash('Login successful.', 'success')
                print("[DEBUG] DB login success")
                return redirect(url_for('admin_dashboard'))
            else:
                flash('Invalid username or password.', 'error')
                print("[DEBUG] Invalid login attempt")

        except Exception as e:
            flash('Database error occurred.', 'error')
            print(f"[ERROR] Database error: {e}")

    return render_template('admin_login.html')

# Admin logout route
@admin_login_bp.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('admin_login.admin_login'))
