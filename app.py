import os
import re
import numpy as np
import xgboost as xgb
import requests
from flask import Flask, request, jsonify, render_template
from urllib.parse import urlparse
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

# Load trained model
model = xgb.XGBClassifier()
model.load_model("model.json")

# Flask app
app = Flask(__name__)

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
    return 1 if 'https' in domain else 0

def shortening_service(url):
    services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|tinyurl|tr\.im|is\.gd|cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|qr\.ae|adf\.ly|bitly\.com|cur\.lv|ity\.im|q\.gs|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net"
    return 1 if re.search(services, url) else 0

def prefix_suffix(url):
    domain = urlparse(url).netloc
    return 1 if '-' in domain else 0

# Placeholder values for DNS/domain/JS-based features
def dns_record(_): return 0
def web_traffic(_): return 0
def domain_age(_): return 0
def domain_end(_): return 0
def iframe(url): return 0
def mouse_over(url): return 0
def right_click(url): return 0
def forwarding(url): return 0

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
        domain_end(domain),
        iframe(url),
        mouse_over(url),
        right_click(url),
        forwarding(url)
    ]
    return np.array(features).reshape(1, -1)

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
    url = request.get_json().get("url")

    try:
        features = extract_features(url)
        prediction = model.predict(features)[0]
        google_flag = check_google_safe_browsing(url)

        if prediction == 1 and google_flag:
            result = "High Risk"
        elif prediction == 1 or google_flag:
            result = "Suspicious"
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
