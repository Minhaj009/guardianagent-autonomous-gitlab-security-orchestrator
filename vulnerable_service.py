import os
import sqlite3
import pickle
import subprocess

# Vulnerability 1: Hardcoded Cloud Secret (AWS Access Key ID & Secret Access Key)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


# Vulnerability 2: SQL Injection
def get_user_by_id(user_id: str):
    """
    Fetches user data from database.
    Vulnerable to SQL Injection via direct string formatting in raw SQL query.
    """
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    # SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    user = cursor.fetchall()
    conn.close()
    return user


# Vulnerability 3: Command Injection
def ping_server(ip_address: str):
    """
    Pings a server to check connectivity.
    Vulnerable to Command Injection by executing unsanitized user input in the shell.
    """
    # Command Injection vulnerability
    cmd = f"ping -c 1 {ip_address}"
    # Using shell=True executes the command via the command shell
    process = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return process.stdout.decode()


# Vulnerability 4: Unsafe Deserialization (Insecure Deserialization via pickle)
def deserialize_session(serialized_data: bytes):
    """
    Restores user session state from cookie.
    Vulnerable to Remote Code Execution via unsafe pickle deserialization.
    """
    # Unsafe Deserialization vulnerability
    return pickle.loads(serialized_data)


# Vulnerability 5: Insecure Direct Object Reference (IDOR)
def get_document_metadata(document_id: int, request_user_id: int):
    """
    Fetches metadata of a private document.
    Vulnerable to IDOR since it doesn't check if the request_user_id has permission
    to access the document_id, only relying on the existence of the document_id.
    """
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    # IDOR vulnerability: Fetches document solely by ID, ignoring the user context
    query = "SELECT id, title, content FROM documents WHERE id = ?"
    cursor.execute(query, (document_id,))
    document = cursor.fetchone()
    conn.close()
    
    # Missing authorization check to verify if request_user_id owns the document
    return document


if __name__ == "__main__":
    print("Vulnerable testing service loaded.")
