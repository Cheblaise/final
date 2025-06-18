from flask import Flask, render_template, send_file, session
import pymysql
import pandas as pd
from io import BytesIO
import os
from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta
from admin_login import admin_login_bp, login_required  # Import login blueprint and decorator

# Set correct template folder path
app = Flask(__name__, template_folder=os.path.join(os.path.dirname(__file__), '..', 'templates'))
app.secret_key = 'your_secure_secret_key_here'  # Replace with a secure random string

# Register the login blueprint
app.register_blueprint(admin_login_bp)

# Database connection
def get_db_connection():
    return pymysql.connect(
        host='localhost',
        user='root',
        password='',
        database='phishing_db'
    )

# Fetch data from DB
def get_all_sites(site_type):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        table = 'phishing_sites' if site_type == 'phishing' else 'safe_sites'
        cursor.execute(f"SELECT url, probability, timestamp FROM {table}")
        data = cursor.fetchall()
        cursor.close()
        conn.close()
        return data
    except Exception as e:
        print(f"Database fetch error: {e}")
        return []

# Fetch scan trends (daily, weekly, monthly)
def get_site_trends():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Daily (last 30 days)
        cursor.execute("""
            SELECT DATE(timestamp) AS period, COUNT(*) AS total
            FROM (
                SELECT timestamp FROM phishing_sites
                UNION ALL
                SELECT timestamp FROM safe_sites
            ) AS combined
            WHERE timestamp >= CURDATE() - INTERVAL 30 DAY
            GROUP BY period
            ORDER BY period
        """)
        daily_raw = cursor.fetchall()
        today = datetime.today().date()
        full_days = [today - timedelta(days=i) for i in reversed(range(30))]
        full_day_strs = [d.isoformat() for d in full_days]
        daily_dict = {row[0].isoformat(): row[1] for row in daily_raw}
        daily_counts_filled = [daily_dict.get(day, 0) for day in full_day_strs]

        # Weekly (last 12 weeks)
        cursor.execute("""
            SELECT YEARWEEK(timestamp, 1) AS yw, COUNT(*) AS total
            FROM (
                SELECT timestamp FROM phishing_sites
                UNION ALL
                SELECT timestamp FROM safe_sites
            ) AS combined
            WHERE timestamp >= CURDATE() - INTERVAL 12 WEEK
            GROUP BY yw
            ORDER BY yw
        """)
        weekly_raw = cursor.fetchall()
        today_dt = datetime.today()
        weeks_list = []
        weekly_labels = []
        for i in reversed(range(12)):
            dt = today_dt - timedelta(weeks=i)
            y, w, _ = dt.isocalendar()
            yw = int(f"{y}{w:02d}")
            weeks_list.append(yw)
            week_start = datetime.strptime(f'{y} {w} 1', '%G %V %u').date()
            week_end = week_start + timedelta(days=6)
            weekly_labels.append(f"Week {w} ({week_start.strftime('%b %d')} - {week_end.strftime('%b %d')})")
        weekly_dict = {row[0]: row[1] for row in weekly_raw}
        weekly_counts_filled = [weekly_dict.get(week, 0) for week in weeks_list]
        weekly_real_labels = [str(w) for w in weeks_list]

        # Monthly (last 12 months)
        cursor.execute("""
            SELECT DATE_FORMAT(timestamp, '%Y-%m') AS period, COUNT(*) AS total
            FROM (
                SELECT timestamp FROM phishing_sites
                UNION ALL
                SELECT timestamp FROM safe_sites
            ) AS combined
            WHERE timestamp >= CURDATE() - INTERVAL 12 MONTH
            GROUP BY period
            ORDER BY period
        """)
        monthly_raw = cursor.fetchall()
        months_list = []
        monthly_labels = []
        current_month = today_dt.replace(day=1)
        for i in reversed(range(12)):
            m = current_month - relativedelta(months=i)
            months_list.append(m.strftime("%Y-%m"))
            monthly_labels.append(m.strftime("%B %Y"))
        monthly_dict = {row[0]: row[1] for row in monthly_raw}
        monthly_counts_filled = [monthly_dict.get(month, 0) for month in months_list]
        monthly_real_labels = months_list

        cursor.close()
        conn.close()

        return {
            'daily': (full_day_strs, daily_counts_filled),
            'daily_real': full_day_strs,
            'weekly': (weekly_labels, weekly_counts_filled),
            'weekly_real': weekly_real_labels,
            'monthly': (monthly_labels, monthly_counts_filled),
            'monthly_real': monthly_real_labels
        }
    except Exception as e:
        print(f"Trend fetch error: {e}")
        return {
            'daily': ([], []), 'daily_real': [],
            'weekly': ([], []), 'weekly_real': [],
            'monthly': ([], []), 'monthly_real': []
        }

# Admin Dashboard (Protected)
@app.route('/')
@login_required
def admin_dashboard():
    phishing = get_all_sites('phishing')
    safe = get_all_sites('safe')
    total_urls = len(phishing) + len(safe)
    return render_template(
        'admin_dashboard.html',
        phishing_sites=phishing,
        safe_sites=safe,
        total_urls=total_urls
    )

# Daily Trends Page (Protected)
@app.route('/trends/daily')
@login_required
def trends_daily():
    trends = get_site_trends()
    return render_template(
        'trend_chart.html',
        title='Daily Scan Trends (Last 30 Days)',
        chart_label='Scans per Day',
        labels=trends['daily'][0],
        counts=trends['daily'][1],
        real_labels=trends['daily_real'],
        x_label='Days',
        y_label='Number of Scans'
    )

# Weekly Trends Page (Protected)
@app.route('/trends/weekly')
@login_required
def trends_weekly():
    trends = get_site_trends()
    return render_template(
        'trend_chart.html',
        title='Weekly Scan Trends (Last 12 Weeks)',
        chart_label='Scans per Week',
        labels=trends['weekly'][0],
        counts=trends['weekly'][1],
        real_labels=trends['weekly_real'],
        x_label='Weeks',
        y_label='Number of Scans'
    )

# Monthly Trends Page (Protected)
@app.route('/trends/monthly')
@login_required
def trends_monthly():
    trends = get_site_trends()
    return render_template(
        'trend_chart.html',
        title='Monthly Scan Trends (Last 12 Months)',
        chart_label='Scans per Month',
        labels=trends['monthly'][0],
        counts=trends['monthly'][1],
        real_labels=trends['monthly_real'],
        x_label='Months',
        y_label='Number of Scans'
    )

# Phishing vs Safe Ratio Pie Chart Page (Protected)
@app.route('/trends/ratio')
@login_required
def phishing_safe_ratio():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM phishing_sites")
        phishing_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM safe_sites")
        safe_count = cursor.fetchone()[0]
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Error fetching phishing/safe counts: {e}")
        phishing_count, safe_count = 0, 0
    return render_template(
        'ratio_chart.html',
        phishing_count=phishing_count,
        safe_count=safe_count
    )

# Export CSV (Protected)
@app.route('/export/<site_type>')
@login_required
def export_sites(site_type):
    records = get_all_sites(site_type)
    df = pd.DataFrame(records, columns=['URL', 'Probability', 'Date/Time'])
    output = BytesIO()
    df.to_csv(output, index=False)
    output.seek(0)
    return send_file(output, download_name=f"{site_type}_sites.csv", as_attachment=True)

# Start the app
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)

