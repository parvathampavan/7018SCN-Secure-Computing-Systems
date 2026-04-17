import os
import hashlib
import re
import time
import json
import hmac
from datetime import datetime

USER_DB = "users.json"
LOG_FILE = "auth.log"
SECRET_KEY = b"super_secret_key"  # used for integrity check

MAX_ATTEMPTS = 3
LOCKOUT_TIME = 30

active_sessions = {}

# Secure Logging (sanitised)

def log_event(message):
    safe_message = re.sub(r"[^\w\s\-:.]", "", message)
    with open(LOG_FILE, "a") as log:
        log.write(f"{datetime.now()} - {safe_message}\n")


# Username validation (STRICT)

def validate_username(username):
    return bool(re.fullmatch(r"[a-zA-Z0-9_]{3,20}", username))


# Strong password validation

def validate_password(password):
    if len(password) < 12:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True


# Secure hashing

def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)

    hashed = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt,
        150000  # increased iterations
    )
    return salt, hashed


# Integrity protection (HMAC)

def generate_signature(data):
    encoded = json.dumps(data, sort_keys=True).encode()
    return hmac.new(SECRET_KEY, encoded, hashlib.sha256).hexdigest()


# Load users safely + integrity check

def load_users():
    if not os.path.exists(USER_DB):
        return {}

    try:
        with open(USER_DB, "r") as f:
            data = json.load(f)

        # Verify integrity
        signature = data.get("_signature")
        users = data.get("users", {})

        if generate_signature(users) != signature:
            print("WARNING: Database tampering detected!")
            log_event("Integrity violation detected")
            return {}

        # Auto-fix missing fields
        for u in users:
            users[u].setdefault("failed_attempts", 0)
            users[u].setdefault("lock_time", 0)

        return users

    except Exception:
        print("Error loading database!")
        log_event("Database load failure")
        return {}


# Save users with integrity protection

def save_users(users):
    data = {
        "users": users,
        "_signature": generate_signature(users)
    }

    with open(USER_DB, "w") as f:
        json.dump(data, f, indent=4)

    try:
        os.chmod(USER_DB, 0o600)
    except:
        pass  # Windows fallback


# Register

def register():
    users = load_users()

    username = input("Enter username: ").strip()

    if not validate_username(username):
        print("Invalid username!")
        return

    if username in users:
        print("Username already exists!")
        return

    password = input("Enter password: ")

    if not validate_password(password):
        print("Weak password!")
        return

    salt, hashed = hash_password(password)

    users[username] = {
        "salt": salt.hex(),
        "hash": hashed.hex(),
        "failed_attempts": 0,
        "lock_time": 0
    }

    save_users(users)
    log_event(f"User registered: {username}")

    print("User registered successfully!")


# Login

def login():
    users = load_users()

    username = input("Enter username: ").strip()

    if username not in users:
        log_event(f"Invalid user attempt: {username}")
        print("User not found!")
        return

    user = users[username]

    # Lockout check
    if user["failed_attempts"] >= MAX_ATTEMPTS:
        if time.time() - user["lock_time"] < LOCKOUT_TIME:
            print("Account locked!")
            log_event(f"Locked account access: {username}")
            return
        else:
            user["failed_attempts"] = 0

    password = input("Enter password: ")

    try:
        salt = bytes.fromhex(user["salt"])
        stored_hash = bytes.fromhex(user["hash"])
    except:
        print("Corrupted user data!")
        log_event(f"Corruption detected: {username}")
        return

    _, new_hash = hash_password(password, salt)

    if hmac.compare_digest(new_hash, stored_hash):
        print("Login successful!")
        log_event(f"Login success: {username}")
        user["failed_attempts"] = 0

        # Real session management
        token = os.urandom(16).hex()
        active_sessions[username] = token
        print(f"Session Token: {token}")

    else:
        print("Invalid password!")
        log_event(f"Failed login: {username}")
        user["failed_attempts"] += 1
        user["lock_time"] = time.time()
        time.sleep(2)

    users[username] = user
    save_users(users)


# Main

def main():
    while True:
        print("\n1. Register\n2. Login\n3. Exit")
        choice = input("Choose option: ")

        if choice == "1":
            register()
        elif choice == "2":
            login()
        elif choice == "3":
            break
        else:
            print("Invalid choice")

if __name__ == "__main__":
    main()