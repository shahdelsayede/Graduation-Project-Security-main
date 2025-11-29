# Web Security Vulnerability Lab 🛡️

A comprehensive web vulnerability scanner and demonstration platform built for my graduation project. This tool helps identify common web security flaws including CSRF, IDOR, SQL Injection, XSS, and Subdomain Enumeration.

## 🚀 Features

* **CSRF Scanner:** Detects forms missing anti-CSRF tokens.
* **IDOR Scanner:** Iterates through ID parameters to find insecure direct object references.
* **SQL Injection Scanner:** Tests parameters for boolean, error-based, and time-based SQLi.
* **Advanced XSS Scanner:** Uses polyglots and unique tokens to detect reflected XSS.
* **Subdomain Enumeration:** Hybrid passive/active scanner using Certificate Transparency logs.

## 🛠️ Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/SeifeldinWalid/Web-Vulnerability-Lab.git
    cd Web-Vulnerability-Lab
    ```

2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

3.  Run the application:
    ```bash
    python app.py
    ```

4.  Open your browser and navigate to `http://127.0.0.1:5000`.

## ⚠️ Disclaimer

This tool is for educational purposes and authorized testing only. Do not use it on servers you do not own or have explicit permission to test.
