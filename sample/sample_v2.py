import sqlite3
import subprocess
import os
import html
from flask import render_template_string
import requests

def get_user_data_safe(user_id):
    # False Positive: SQL Injection (Parameterized)
    # The tool should detect 'cursor.execute' as a sink, but finding '?' as sanitizer.
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    return cursor.fetchall()

def health_check_unsafe(ip_address):
    # True Positive: Command Injection
    # The tool should detect 'subprocess.run' and lack of sanitization
    command = f"ping -c 1 {ip_address}"
    subprocess.run(command, shell=True)

def fetch_external_status(node_url):
    # True Positive: SSRF
    # User input directly in URL
    url = f"https://api.internal.com/stats?node={node_url}"
    # SINK: requests.get
    requests.get(url) 

def show_profile_safe(name):
    # False Positive: XSS (Sanitized)
    # SINK: render_template_string
    # SANITIZER: html.escape
    clean_name = html.escape(name)
    render_template_string(f"<div>Hello {clean_name}</div>")
