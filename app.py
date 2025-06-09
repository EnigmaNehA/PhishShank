import os
import re
import numpy as np
import xgboost as xgb
import requests
from flask import Flask, request, jsonify, render_template
from urllib.parse import urlparse
from dotenv import load_dotenv
from datetime import datetime
import socket
import whois
from flask_cors import CORS

!pip install tranco tldextract

# Flask app
app = Flask(__name__ , static_folder='static')
CORS(app)


# Load environment variables
load_dotenv()
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

# Load trained model
model = xgb.XGBClassifier()
model.load_model("model.json")

# ----------------------------------------
# 🔍 Feature Extraction Functions (from your notebook)
# ----------------------------------------

def has_ip_address(url):
    try:
        ip_pattern = re.compile(r'http[s]?://(?:\d{1,3}\.){3}\d{1,3}')
        return 1 if ip_pattern.match(url) else 0
    except:
        return 0

def has_at_symbol(url):
    return 1 if "@" in url else 0

def url_length(url):
    return 1 if len(url) >= 54 else 0

def url_depth(url):
    path = urlparse(url).path
    return path.count('/')

def redirection(url):
    return 1 if '//' in url[8:] else 0

def https_in_domain(url):
    domain = urlparse(url).netloc
    if ('http' or 'https') in url:
        return 0
    else:
        return 1

def shortening_service(url):
    services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|tinyurl|tr\.im|is\.gd|cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|qr\.ae|adf\.ly|bitly\.com|cur\.lv|ity\.im|q\.gs|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net"
    return 1 if re.search(services, url) else 0

def prefix_suffix(url):
    domain = urlparse(url).netloc
    return 1 if '-' in domain else 0

def dns_record(url):
    domain = url.split('//')[-1].split('/')[0]
    try:
        socket.gethostbyname(domain)
        return 0
    except:
        return 1

import os
import csv
import tldextract
import requests
import zipfile
from io import BytesIO

# Global variable to store loaded domains
umbrella_domains = set()

def load_umbrella_list():
    """
    Downloads and loads the Umbrella Top 1M list into memory.
    """
    global umbrella_domains
    try:
        if umbrella_domains:
            return  # Already loaded

        # Download the zip file from Umbrella
        url = "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"
        response = requests.get(url)
        with zipfile.ZipFile(BytesIO(response.content)) as thezip:
            with thezip.open("top-1m.csv") as thefile:
                csv_reader = csv.reader(map(lambda b: b.decode('utf-8'), thefile))
                for row in csv_reader:
                    if len(row) > 1:
                        domain = row[1].strip().lower()
                        umbrella_domains.add(domain)
    except:
        umbrella_domains = set()

def web_traffic(url):
    """
    Returns 0 if domain is in Umbrella Top 1M, 1 otherwise.
    """
    try:
        if not umbrella_domains:
            load_umbrella_list()

        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}".lower()
        return 0 if domain in umbrella_domains else 1
    except:
        return 1

def domain_age(url):
    try:
        domain = whois.whois(url)
        if domain.creation_date is None or domain.expiration_date is None:
            return 1
        if isinstance(domain.creation_date, list):
            creation_date = domain.creation_date[0]
        else:
            creation_date = domain.creation_date
        age = (datetime.now() - creation_date).days
        return 1 if age < 180 else 0
    except:
        return 1

def domain_end(url):
    try:
        domain = whois.whois(url)
        if domain.expiration_date is None:
            return 1
        if isinstance(domain.expiration_date, list):
            expiration_date = domain.expiration_date[0]
        else:
            expiration_date = domain.expiration_date
        end = (expiration_date - datetime.now()).days
        return 1 if end < 180 else 0
    except:
        return 1

def iframe(response):
    return 1 if "<iframe" in response else 0

def mouse_over(response):
    return 1 if "onmouseover" in response else 0

def right_click(response):
    return 1 if "event.button==2" in response else 0

def forwarding(response):
    return 1 if response.count('window.open') > 1 else 0

def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc

    features = [
        has_ip_address(url),
        has_at_symbol(url),
        url_length(url),
        url_depth(url),
        redirection(url),
        https_in_domain(url),
        shortening_service(url),
        prefix_suffix(url),
        dns_record(domain),
        web_traffic(domain),
        domain_age(domain),
        domain_end(domain)
    ]

    try:
        response = urllib.request.urlopen(url).read().decode()
    except:
        response = ""

    features.append(iframe(response))
    features.append(mouse_over(response))
    features.append(right_click(response))
    features.append(forwarding(response))

    return np.array([features])


# ----------------------------------------
# 🔐 Google Safe Browsing Check
# ----------------------------------------

def check_google_safe_browsing(url):
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
    payload = {
        "client": {"clientId": "phishing-detector", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        response = requests.post(api_url, json=payload)
        data = response.json()
        return data.get("matches") is not None
    except:
        return False

# ----------------------------------------
# 🌐 Flask Routes
# ----------------------------------------

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/predict', methods=["POST"])
def check_url():
    try:
        # Get URL from request
        data = request.get_json()
        url = data.get('url')  # Correct way to extract URL

        # Extract features from the URL for prediction
        features = extract_features(url)
        prediction = model.predict(features)[0]

        # Check against Google Safe Browsing
        google_flag = check_google_safe_browsing(url)

        # Determine risk level
        if prediction == 1 or google_flag:
            result = "High Risk"
        else:
            result = "Safe"

        return jsonify(result=result)
    
    except Exception as e:
        return jsonify(error=str(e)), 500

# ----------------------------------------
# 🚀 Run App (for local testing only)
# ----------------------------------------

if __name__ == '__main__':
    app.run(debug=True)
