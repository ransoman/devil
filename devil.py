import logging
from telegram import Update
from telegram.ext import Updater, CommandHandler, CallbackContext
import requests
import random
import time
import json
import os
import re
import subprocess
import socket

# ===========================
# API KEYS dan Configs
OWNER_ID = 7836468443  # Ganti dengan ID Telegram pemilik bot
API_KEY = '7566111301:AAH5tuEOowkjDr4yrYBj_2-vqq6d6tmgQyU'
DEBUG = True

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

# ===========================
# Command: /start
def start(update: Update, context: CallbackContext):
    update.message.reply_text("Welcome to X-BOT vFINAL!\nUse /help for available commands.")

# ===========================
# Command: /help
def help(update: Update, context: CallbackContext):
    update.message.reply_text("Available commands:\n/start - Start the bot\n/vuln <url> - Check for vulnerabilities\n/iptrace <IP> - Trace IP location\n/ddos <target> - Start DDoS simulation\n/userinfo <username> - OSINT via Telegram Username")

# ===========================
# OSINT Tools
def iptrace(update: Update, context: CallbackContext):
    if len(context.args) < 1:
        update.message.reply_text("Usage: /iptrace <IP>")
        return
    ip = context.args[0]
    try:
        response = requests.get(f'https://ipinfo.io/{ip}/json')
        data = response.json()
        location = data.get('loc', 'Unknown')
        update.message.reply_text(f"Location for {ip}: {location}")
    except requests.exceptions.RequestException as e:
        update.message.reply_text(f"Error tracing IP: {str(e)}")

def whois(update: Update, context: CallbackContext):
    if len(context.args) < 1:
        update.message.reply_text("Usage: /whois <domain>")
        return
    domain = context.args[0]
    try:
        response = requests.get(f'https://whoisapi.com/whois/{domain}')
        data = response.json()
        update.message.reply_text(f"WHOIS Data: {json.dumps(data, indent=2)}")
    except requests.exceptions.RequestException as e:
        update.message.reply_text(f"Error fetching WHOIS data: {str(e)}")

# ===========================
# OSINT via Telegram Username
def userinfo(update: Update, context: CallbackContext):
    if len(context.args) < 1:
        update.message.reply_text("Usage: /userinfo <telegram_username>")
        return
    username = context.args[0].replace("@", "")
    try:
        update.message.reply_text(f"🔍 Searching Telegram username: @{username}... (Note: Limited by API)")
        info = f"Username: @{username}\nNo public API to extract more due to Telegram privacy.\nSuggest checking via Telegram search or third-party tools."
        update.message.reply_text(info)
    except Exception as e:
        update.message.reply_text(f"Error: {str(e)}")

# ===========================
# Vulnerability Scanner (SQLi & XSS)
def vuln(update: Update, context: CallbackContext):
    if len(context.args) < 1:
        update.message.reply_text("Usage: /vuln <target_url>")
        return

    target_url = context.args[0]

    # SQLi Testing
    sqli_payloads = [
        "' OR 1=1 --", 
        "' OR 'a'='a", 
        "' UNION SELECT NULL, username, password FROM users --"
    ]

    sqli_results = []
    for payload in sqli_payloads:
        test_url = f"{target_url}{payload}"
        try:
            response = requests.get(test_url)
            if "error" in response.text or "mysql" in response.text or "syntax" in response.text:
                sqli_results.append(f"Potential SQLi found with payload: {payload}")
        except requests.exceptions.RequestException as e:
            sqli_results.append(f"Error with URL: {str(e)}")

    # XSS Testing
    xss_payloads = [
        '<script>alert("XSS")</script>', 
        '<img src="x" onerror="alert(1)">',
        '<svg/onload=alert(1)>'
    ]

    xss_results = []
    for payload in xss_payloads:
        test_url = f"{target_url}?q={payload}"
        try:
            response = requests.get(test_url)
            if payload in response.text:
                xss_results.append(f"Potential XSS found with payload: {payload}")
        except requests.exceptions.RequestException as e:
            xss_results.append(f"Error with URL: {str(e)}")

    result_message = "Vulnerability Scan Results:\n\n"
    if sqli_results:
        result_message += "SQLi Vulnerabilities:\n"
        for res in sqli_results:
            result_message += f"- {res}\n"
    else:
        result_message += "No SQLi vulnerabilities detected.\n"

    if xss_results:
        result_message += "\nXSS Vulnerabilities:\n"
        for res in xss_results:
            result_message += f"- {res}\n"
    else:
        result_message += "No XSS vulnerabilities detected.\n"

    update.message.reply_text(result_message)

# ===========================
# DDoS Simulator (7-layer)
def ddos(update: Update, context: CallbackContext):
    if len(context.args) < 3:
        update.message.reply_text("Usage: /ddos <host> <port> <time> <method>")
        return

    host = context.args[0]
    port = context.args[1]
    time_duration = int(context.args[2])
    method = context.args[3]

    if method not in ["HTTP", "UDP", "TCP"]:
        update.message.reply_text("Invalid method. Use HTTP, UDP, or TCP.")
        return

    update.message.reply_text(f"Starting {method} DDoS attack on {host}:{port} for {time_duration} seconds.")
    time.sleep(time_duration)
    update.message.reply_text(f"DDoS attack on {host}:{port} completed.")

# ===========================
# Web Shell Notifier (Monitoring)
def shellfinder(update: Update, context: CallbackContext):
    update.message.reply_text("Scanning for web shells...")
    response = requests.get('http://example.com/path/to/scan')
    if 'c99' in response.text or 'r57' in response.text:
        update.message.reply_text("Potential web shell found!")
    else:
        update.message.reply_text("No web shells detected.")

# ===========================
# Stealth Features (OWNER only)
def stealth_logger(update: Update, context: CallbackContext):
    if update.message.from_user.id != OWNER_ID:
        update.message.reply_text("Unauthorized access")
        return
    with open("stealth_log.txt", "a") as file:
        file.write(f"{update.message.from_user.username}: {update.message.text}\n")
    update.message.reply_text("Message logged silently.")

def auto_dump_sender(update: Update, context: CallbackContext):
    if update.message.from_user.id != OWNER_ID:
        update.message.reply_text("Unauthorized access")
        return
    with open("stealth_log.txt", "r") as file:
        content = file.read()
    update.message.reply_text(content)

# ===========================
# Web Shell Detection (Advanced)
def web_shell_detection(update: Update, context: CallbackContext):
    update.message.reply_text("Starting web shell detection...")
    shells = ['c99.php', 'r57.php', 'wso.php', 'deface.php']
    for shell in shells:
        url = f"http://targetsite.com/{shell}"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                update.message.reply_text(f"Web shell {shell} detected!")
            else:
                update.message.reply_text(f"No shell detected for {shell}.")
        except requests.exceptions.RequestException as e:
            update.message.reply_text(f"Error checking for {shell}: {str(e)}")

# ===========================
# Main function (FIXED)
def main():
    try:
        updater = Updater(token=API_KEY, use_context=True)
        dp = updater.dispatcher

        dp.add_handler(CommandHandler("start", start))
        dp.add_handler(CommandHandler("help", help))
        dp.add_handler(CommandHandler("iptrace", iptrace))
        dp.add_handler(CommandHandler("whois", whois))
        dp.add_handler(CommandHandler("vuln", vuln))
        dp.add_handler(CommandHandler("ddos", ddos))
        dp.add_handler(CommandHandler("shellfinder", shellfinder))
        dp.add_handler(CommandHandler("stealth_logger", stealth_logger))
        dp.add_handler(CommandHandler("auto_dump_sender", auto_dump_sender))
        dp.add_handler(CommandHandler("web_shell_detection", web_shell_detection))
        dp.add_handler(CommandHandler("userinfo", userinfo))

        logging.info("Bot sedang berjalan...")
        updater.start_polling()
        updater.idle()
    except Exception as e:
        logging.error(f"Error: {str(e)}")
        raise

if __name__ == '__main__':
    main()
