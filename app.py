import os
import re
import csv
import zipfile
import socket
import whois
import numpy as np
import requests
import tldextract
import xgboost as xgb
import urllib.request
from datetime import datetime
from flask import Flask, request, jsonify, render_template
from urllib.parse import urlparse
from flask_cors import CORS
from dotenv import load_dotenv

# Flask app setup
app = Flask(__name__, static_folder='static')
CORS(app)

# Load environment variables
load_dotenv()
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

# Load trained XGBoost model
model = xgb.XGBClassifier()
model.load_model("model.json")

# ----------------------------------------
# 🔍 Feature Extraction Functions
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
    return urlparse(url).path.count('/')

def redirection(url):
    return 1 if '//' in url[8:] else 0

def https_in_domain(url):
    domain = urlparse(url).netloc
    return 0 if ('http' in domain or 'https' in domain) else 1

def shortening_service(url):
    services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|tinyurl|tr\.im|is\.gd|cli\.gs|" \
               r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|" \
               r"snipurl\.com|short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|" \
               r"snipr\.com|fic\.kr|loopt\.us|doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|" \
               r"om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|qr\.ae|adf\.ly|bitly\.com|cur\.lv|" \
               r"ity\.im|q\.gs|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|" \
               r"u\.bb|yourls\.org|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|" \
               r"qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net"
    return 1 if re.search(services, url) else 0

def prefix_suffix(url):
    domain = urlparse(url).netloc
    return 1 if '-' in domain else 0

def dns_record(domain):
    try:
        socket.gethostbyname(domain)
        return 0
    except:
        return 1

# ----------------------------------------
# 🌐 Top 1M Domain Check (Local File Version)
# ----------------------------------------

umbrella_domains = set()

def load_umbrella_list():
    """
    Loads the Umbrella Top 1M list from local zip file into memory.
    Assumes 'top-1m.csv.zip' is present in the same directory.
    """
    global umbrella_domains
    try:
        if umbrella_domains:
            return  # Already loaded
        zip_path = os.path.join(os.path.dirname(__file__), "top-1m.csv.zip")
        with zipfile.ZipFile(zip_path, 'r') as thezip:
            with thezip.open("top-1m.csv") as thefile:
                csv_reader = csv.reader(map(lambda b: b.decode('utf-8'), thefile))
                for row in csv_reader:
                    if len(row) > 1:
                        domain = row[1].strip().lower()
                        umbrella_domains.add(domain)
    except Exception as e:
        print("Error loading umbrella list:", e)
        umbrella_domains = set()

def web_traffic(url):
    try:
        if not umbrella_domains:
            load_umbrella_list()
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}".lower()
        return 0 if domain in umbrella_domains else 1
    except:
        return 1

# ----------------------------------------
# 🌐 Domain Age Features
# ----------------------------------------

def domain_age(url):
    try:
        domain = whois.whois(url)
        creation_date = domain.creation_date[0] if isinstance(domain.creation_date, list) else domain.creation_date
        if creation_date is None:
            return 1
        age = (datetime.now() - creation_date).days
        return 1 if age < 180 else 0
    except:
        return 1

def domain_end(url):
    try:
        domain = whois.whois(url)
        expiration_date = domain.expiration_date[0] if isinstance(domain.expiration_date, list) else domain.expiration_date
        if expiration_date is None:
            return 1
        end = (expiration_date - datetime.now()).days
        return 1 if end < 180 else 0
    except:
        return 1

# ----------------------------------------
# 🧪 HTML/JS Based Features
# ----------------------------------------

def iframe(response):
    return 1 if "<iframe" in response else 0

def mouse_over(response):
    return 1 if "onmouseover" in response else 0

def right_click(response):
    return 1 if "event.button==2" in response else 0

def forwarding(response):
    return 1 if response.count('window.open') > 1 else 0

# ----------------------------------------
# 📊 Full Feature Extraction Pipeline
# ----------------------------------------

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

    features.extend([
        iframe(response),
        mouse_over(response),
        right_click(response),
        forwarding(response)
    ])

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
        data = request.get_json()
        url = data.get('url')
        features = extract_features(url)
        prediction = model.predict(features)[0]
        google_flag = check_google_safe_browsing(url)
        result = "High Risk" if prediction == 1 or google_flag else "Safe"
        return jsonify(result=result)
    except Exception as e:
        return jsonify(error=str(e)), 500

# ----------------------------------------
# 🚀 Run (for local testing)
# ----------------------------------------

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)

