# import_csv_to_db.py

import pandas as pd
import pymysql
from config import DB_CONFIG

# Load CSV file
csv_path = 'Phishing_Websites_Data.csv'  # Ensure it's in the same folder or use full path
df = pd.read_csv(csv_path)

# Connect to MySQL
connection = pymysql.connect(**DB_CONFIG)
cursor = connection.cursor()

# Ensure the correct database is selected
cursor.execute(f"USE {DB_CONFIG['database']}")

# Create table if it doesn't exist
create_table_query = """
CREATE TABLE IF NOT EXISTS phishing_data (
    having_IP_Address INT,
    URL_Length INT,
    Shortining_Service INT,
    having_At_Symbol INT,
    double_slash_redirecting INT,
    Prefix_Suffix INT,
    having_Sub_Domain INT,
    SSLfinal_State INT,
    Domain_registeration_length INT,
    Favicon INT,
    port INT,
    HTTPS_token INT,
    Request_URL INT,
    URL_of_Anchor INT,
    Links_in_tags INT,
    SFH INT,
    Submitting_to_email INT,
    Abnormal_URL INT,
    Redirect INT,
    on_mouseover INT,
    RightClick INT,
    popUpWidnow INT,
    Iframe INT,
    age_of_domain INT,
    DNSRecord INT,
    web_traffic INT,
    Page_Rank INT,
    Google_Index INT,
    Links_pointing_to_page INT,
    Statistical_report INT,
    Result INT
)
"""
cursor.execute(create_table_query)

# Insert data row by row
for _, row in df.iterrows():
    cursor.execute("""
        INSERT INTO phishing_data VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                                          %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                                          %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, tuple(row))

connection.commit()
connection.close()

print("CSV data imported successfully into the MySQL database.")
