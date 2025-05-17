import os
import re
import socket
import logging
import requests
import whois
import tldextract
import numpy as np
import xgboost as xgb  # <-- Changed
from urllib.parse import urlparse
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
CORS(app)

GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
MODEL_PATH = "model.json"  # <-- Updated

# Load XGBoost model from .json file
model = xgb.Booster()
model.load_model(MODEL_PATH)

# === [Feature extraction functions remain unchanged] ===
def getDomain(url):
    domain = urlparse(url).netloc
    if re.match(r"^www\.", domain):
        domain = domain.replace("www.", "", 1)
    return domain

def havingIP(url):
    try:
        domain = urlparse(url).netloc
        socket.inet_aton(domain)  # Checks IPv4
        return 1
    except:
        return 0

def haveAtSymbol(url):
    return 1 if "@" in url else 0

def URL_length(url):
    return 1 if len(url) > 54 else 0

def getDepth(url):
    try:
        path_segments = urlparse(url).path.split('/')
        return sum(1 for seg in path_segments if seg)
    except:
        return 0

def redirection(url):
    try:
        pos = url.rfind('//')
        return 1 if pos > 7 else 0  # After "http://" or "https://"
    except:
        return 0

def httpDomain(url):
    try:
        return 0 if urlparse(url).scheme == "https" else 1
    except:
        return 1

shortening_services = r"(?:bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|" \
                      r"cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|" \
                      r"snipurl\.com|short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|" \
                      r"fic\.kr|loopt\.us|doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|" \
                      r"bit\.do|lnkd\.in|db\.tt|qr\.ae|adf\.ly|bitly\.com|cur\.lv|tinyurl\.com|ity\.im|" \
                      r"q\.gs|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|" \
                      r"yourls\.org|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|" \
                      r"1url\.com|tweez\.me|v\.gd|link\.zip\.net)"

def is_shortening_service(url):
    if not isinstance(url, str):
        return 0
    return 1 if re.search(shortening_services, url) else 0

def prefix_suffix(url):
    try:
        return 1 if '-' in urlparse(url).netloc else 0
    except:
        return 0

def check_dns_record(domain_name):
    try:
        socket.gethostbyname(domain_name)
        w = whois.whois(domain_name)
        if not w or not w.domain_name:
            return 1
        return 0
    except:
        return 1

# Global cache for umbrella domains
umbrella_domains = set()

def load_umbrella_list():
    global umbrella_domains
    if umbrella_domains:
        return
    try:
        url = "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"
        r = requests.get(url)
        from io import BytesIO
        import zipfile, csv
        with zipfile.ZipFile(BytesIO(r.content)) as z:
            with z.open("top-1m.csv") as f:
                reader = csv.reader(map(lambda b: b.decode("utf-8"), f))
                for row in reader:
                    if len(row) > 1:
                        umbrella_domains.add(row[1].strip().lower())
    except Exception as e:
        logging.warning(f"Could not load umbrella list: {e}")

def extract_web_traffic(url):
    try:
        if not umbrella_domains:
            load_umbrella_list()
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}".lower()
        return 0 if domain in umbrella_domains else 1
    except:
        return 1

def get_domain_info(domain_name):
    try:
        w = whois.whois(domain_name)
        creation_date = w.creation_date
        expiration_date = w.expiration_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        return creation_date, expiration_date
    except:
        return None, None

def domain_age(domain_name):
    creation_date, expiration_date = get_domain_info(domain_name)
    if not creation_date or not expiration_date:
        return 1
    try:
        if isinstance(creation_date, str):
            creation_date = datetime.strptime(creation_date[:10], "%Y-%m-%d")
        if isinstance(expiration_date, str):
            expiration_date = datetime.strptime(expiration_date[:10], "%Y-%m-%d")
        age_months = (expiration_date - creation_date).days / 30
        return 1 if age_months < 6 else 0
    except:
        return 1

def domainEnd(domain_name):
    creation_date, expiration_date = get_domain_info(domain_name)
    if not creation_date or not expiration_date:
        return 0
    try:
        if isinstance(creation_date, str):
            creation_date = datetime.strptime(creation_date[:10], "%Y-%m-%d")
        if isinstance(expiration_date, str):
            expiration_date = datetime.strptime(expiration_date[:10], "%Y-%m-%d")
        age_months = (expiration_date - creation_date).days / 30
        return 1 if age_months > 12 else 0
    except:
        return 0

def iframe(url):
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        r = requests.get(url, headers=headers, timeout=5)
        if re.search(r"<iframe", r.text, re.IGNORECASE):
            return 1
        return 0
    except:
        return 1

def mouseover(url):
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        r = requests.get(url, headers=headers, timeout=5)
        if re.search(r"onmouseover\s*=", r.text, re.IGNORECASE):
            return 1
        return 0
    except:
        return 1

def right_click(url):
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        r = requests.get(url, headers=headers, timeout=5)
        if re.search(r"event\.button\s*==\s*2", r.text):
            return 0
        return 1
    except:
        return 1

def forwarding(url):
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        r = requests.get(url, headers=headers, timeout=5, allow_redirects=True)
        return 1 if len(r.history) > 3 else 0
    except:
        return 1


# Sample vector wrapper for Booster model
def extract_features_from_url(url):
    domain = getDomain(url)
    features = [
        havingIP(url),
        haveAtSymbol(url),
        URL_length(url),
        getDepth(url),
        redirection(url),
        httpDomain(url),
        is_shortening_service(url),
        prefix_suffix(url),
        check_dns_record(domain),
        extract_web_traffic(url),
        domain_age(domain),
        domainEnd(domain),
        iframe(url),
        mouseover(url),
        right_click(url),
        forwarding(url),
        check_google_safe_browsing(url)
    ]
    dmatrix = xgb.DMatrix(np.array([features]))  # wrap in DMatrix
    return dmatrix

# === Predict route updated for Booster inference ===
@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({"error": "Missing 'url' in request"}), 400

    url = data["url"].strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        dmatrix = extract_features_from_url(url)
        prediction = int(model.predict(dmatrix)[0] >= 0.5)  # Binary decision
        result = "Phishing" if prediction == 1 else "Legitimate"
        return jsonify({"url": url, "prediction": result})
    except Exception as e:
        logging.error(f"Prediction error: {e}")
        return jsonify({"error": "Internal server error"}), 500

# Entry point
if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
