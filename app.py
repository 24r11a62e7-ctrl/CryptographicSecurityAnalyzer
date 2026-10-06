from flask import Flask, render_template, request
import json
import os

app = Flask(__name__)


# Load security rules
def load_rules():
    base_folder = os.path.dirname(os.path.abspath(__file__))
    rules_file = os.path.join(base_folder, "rules.json")

    with open(rules_file, "r", encoding="utf-8") as file:
        return json.load(file)


# Analyze the entered cryptographic configuration
def analyze(data):

    rules = load_rules()
    findings = []

    password = data["password"]
    hash_algorithm = data["hash_algorithm"]
    hash_result = data["hash_result"]
    encryption_algorithm = data["encryption_algorithm"]
    encryption_mode = data["encryption_mode"]
    encryption_key = data["encryption_key"]

    # -----------------------------
    # Password analysis
    # -----------------------------

    password_score = 0

    if len(password) >= 8:
        password_score += 1

    if any(c.isupper() for c in password):
        password_score += 1

    if any(c.islower() for c in password):
        password_score += 1

    if any(c.isdigit() for c in password):
        password_score += 1

    if any(not c.isalnum() for c in password):
        password_score += 1

    if password_score <= 2:
        password_strength = "WEAK"
    elif password_score <= 4:
        password_strength = "MEDIUM"
    else:
        password_strength = "STRONG"


    # -----------------------------
    # Hash analysis
    # -----------------------------

    if hash_algorithm in ["MD5", "SHA-1"]:

        rule = rules[hash_algorithm]

        findings.append({
            "title": rule["title"],
            "severity": rule["severity"],
            "description": rule["description"],
            "recommendation": rule["recommendation"]
        })


    # -----------------------------
    # Encryption analysis
    # -----------------------------

    if encryption_algorithm == "DES":

        rule = rules["DES"]

        findings.append({
            "title": rule["title"],
            "severity": rule["severity"],
            "description": rule["description"],
            "recommendation": rule["recommendation"]
        })


    if encryption_algorithm == "3DES":

        rule = rules["3DES"]

        findings.append({
            "title": rule["title"],
            "severity": rule["severity"],
            "description": rule["description"],
            "recommendation": rule["recommendation"]
        })


    # -----------------------------
    # AES mode analysis
    # -----------------------------

    if encryption_algorithm == "AES" and encryption_mode == "ECB":

        rule = rules["AES-ECB"]

        findings.append({
            "title": rule["title"],
            "severity": rule["severity"],
            "description": rule["description"],
            "recommendation": rule["recommendation"]
        })


    # -----------------------------
    # Key analysis
    # -----------------------------

    key_length = len(encryption_key.encode()) * 8

    if encryption_algorithm == "AES":

        if key_length not in [128, 192, 256]:

            findings.append({
                "title": "Invalid AES Key Length",
                "severity": "HIGH",
                "description": "AES requires a key size of 128, 192, or 256 bits.",
                "recommendation": "Use a valid AES key length."
            })


    if encryption_algorithm == "DES":

        if key_length < 64:

            findings.append({
                "title": "Weak DES Key",
                "severity": "HIGH",
                "description": "The supplied DES key is shorter than the expected DES key size.",
                "recommendation": "Avoid DES and use AES instead."
            })


    # -----------------------------
    # Hardcoded key check
    # -----------------------------

    if encryption_key:

        if encryption_key.lower() in password.lower():

            findings.append({
                "title": "Potential Key Reuse",
                "severity": "HIGH",
                "description": "The encryption key appears to be reused as part of the password.",
                "recommendation": "Use independent cryptographic keys and passwords."
            })


    return {
        "password_strength": password_strength,
        "password_length": len(password),
        "hash_algorithm": hash_algorithm,
        "hash_result": hash_result,
        "encryption_algorithm": encryption_algorithm,
        "encryption_mode": encryption_mode,
        "key_length": key_length,
        "findings": findings
    }


# Home page
@app.route("/")
def home():
    return render_template("index.html")


# Analyze button
@app.route("/analyze", methods=["POST"])
def analyze_page():

    data = {
        "password": request.form.get("password", ""),
        "hash_algorithm": request.form.get("hash_algorithm", ""),
        "hash_result": request.form.get("hash_result", ""),
        "encryption_algorithm": request.form.get("encryption_algorithm", ""),
        "encryption_mode": request.form.get("encryption_mode", ""),
        "encryption_key": request.form.get("encryption_key", "")
    }

    result = analyze(data)

    return render_template(
        "report.html",
        result=result
    )


if __name__ == "__main__":
    app.run(debug=True)