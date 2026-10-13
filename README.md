# Shadow AI Sentinel
A Sensitive Data Detection and Redaction System (college RDBMS project).
It checks text for emails, phone numbers, API-key-like strings and passwords
BEFORE you paste it into an AI chatbot. It does NOT intercept messages on
external chatbot websites, and it never stores your original text.

## Setup on Windows (VS Code terminal, PowerShell)
1. Install Python 3.10+, MySQL Server 8.0.16+ and MySQL Workbench.
2. Open this folder in VS Code (File > Open Folder).
3. Open a terminal (Ctrl + `) and create a virtual environment:
       python -m venv venv
       venv\Scripts\activate
   If PowerShell blocks activation, run once:
       Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
4. Install packages:
       pip install -r requirements.txt
5. Create the database: open schema.sql in MySQL Workbench and click the
   lightning bolt.
6. Store your DB password safely:
       copy .env.example .env
   Edit .env and put your real MySQL password. (.env is never shared.)
7. Run:
       python app.py
8. Open http://127.0.0.1:5000/db-test in Chrome.

Stop the app: press Ctrl + C in the terminal.
Restart: run `python app.py` again.
