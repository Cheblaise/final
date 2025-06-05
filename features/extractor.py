# features/extractor.py

import re
import socket
import urllib
from urllib.parse import urlparse
import whois
import datetime

def has_ip_address(url):
    try:
        ip = socket.gethostbyname(urlparse(url).netloc)
        return -1
    except:
        return 1

def get_domain(url):
    return urlparse(url).netloc

def extract_features(url):
    features = {}

    features['having_IP_Address'] = has_ip_address(url)
    features['URL_Length'] = 1 if len(url) >= 75 else (0 if len(url) > 54 else -1)
    features['Shortining_Service'] = 1 if re.search(r'(bit\.ly|goo\.gl|tinyurl\.com|ow\.ly)', url) else -1
    features['having_At_Symbol'] = 1 if "@" in url else -1
    features['double_slash_redirecting'] = 1 if "//" in url[7:] else -1
    features['Prefix_Suffix'] = 1 if '-' in get_domain(url) else -1
    features['having_Sub_Domain'] = (
        -1 if urlparse(url).netloc.count('.') == 1 else
        0 if urlparse(url).netloc.count('.') == 2 else
        1
    )
    features['SSLfinal_State'] = -1  # placeholder; requires requests/cert validation
    features['Domain_registeration_length'] = -1  # placeholder; requires whois
    features['Favicon'] = 1  # assume correct favicon for now
    features['port'] = 1  # assume standard ports used
    features['HTTPS_token'] = -1 if 'https' in get_domain(url) else 1
    features['Request_URL'] = 1  # placeholder; requires page analysis
    features['URL_of_Anchor'] = 0
    features['Links_in_tags'] = 1
    features['SFH'] = -1
    features['Submitting_to_email'] = -1 if 'mailto:' in url else 1
    features['Abnormal_URL'] = -1
    features['Redirect'] = 0
    features['on_mouseover'] = 1
    features['RightClick'] = 1
    features['popUpWidnow'] = 1
    features['Iframe'] = 1
    features['age_of_domain'] = -1  # placeholder
    features['DNSRecord'] = -1
    features['web_traffic'] = 0
    features['Page_Rank'] = -1
    features['Google_Index'] = 1
    features['Links_pointing_to_page'] = 0
    features['Statistical_report'] = -1

    return features
