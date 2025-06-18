from flask import Blueprint, render_template, request, redirect, url_for, flash, session
import pymysql
from werkzeug.security import generate_password_hash, check_password_hash

user_auth = Blueprint('user_auth', __name__, template_folder='templates')

def get_db_connection():
    return pymysql.connect(
        host='localhost',
        user='root',
        password='',
        database='phishing_db',
        cursorclass=pymysql.cursors.DictCursor
    )

@user_auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Please enter both username and password.', 'error')
            return redirect(url_for('user_auth.login'))

        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['username'] = user['username']
            flash('Login successful!', 'success')
            return redirect(url_for('home'))  # Ensure 'home' route exists
        else:
            flash('Invalid username or password', 'error')
            return redirect(url_for('user_auth.login'))

    return render_template('user_auth.html')

@user_auth.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        flash('Username and password are required.', 'error')
        return redirect(url_for('user_auth.login'))

    hashed_password = generate_password_hash(password)

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            if cursor.fetchone():
                flash('Username already exists', 'error')
                return redirect(url_for('user_auth.login'))

            cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_password))
            conn.commit()
            flash('Registration successful! You can now log in.', 'success')
    finally:
        conn.close()

    return redirect(url_for('user_auth.login'))

@user_auth.route('/logout')
def logout():
    session.pop('username', None)
    flash('Logged out successfully.', 'success')
    return redirect(url_for('user_auth.login'))
