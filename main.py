import re
import sqlite3
from random import randint

import eel
import firebase_admin
import jwt
from firebase_admin import credentials
from firebase_admin import db
from datetime import datetime
import time
import uuid

from gevent import os
from twilio.rest import Client

import bcrypt

# Your Account SID from twilio.com/console
account_sid = ""
# Your Auth Token from twilio.com/console
auth_token = ""

now = datetime.now()
dt_string = now.strftime("%d/%m/%Y %H:%M:%S")

# Fetch the service account key JSON file contents
cred = credentials.Certificate('eel-client-1ed295539ad0.json')

eel.init('static')

def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


# Checks if input string is email address
def is_input_email(value):
    if len(value.strip().lower().replace(" ", "")) > 7:
        return bool(
            re.match("^.+@(\[?)[a-zA-Z0-9-.]+.([a-zA-Z]{2,3}|[0-9]{1,3})(]?)$", value.strip().lower().replace(" ", "")))
    else:
        return False


# Finds user by email checks if user exists in database
def find_user_by_email(email_address):
    # print('CHECKING USER BY EMAIL')
    conn = sqlite3.connect('identifier.sqlite')
    conn.row_factory = dict_factory
    curs = conn.cursor()
    curs.execute("SELECT * from users where email = (?)", [email_address.strip().lower().replace(" ", "")])
    user = curs.fetchone()
    conn.close()
    return user


def find_user_by_id(user_id):
    conn = sqlite3.connect('identifier.sqlite')
    conn.row_factory = dict_factory
    curs = conn.cursor()
    curs.execute("SELECT * from users where id = (?)", [user_id])
    user = curs.fetchone()
    conn.close()
    return user


# Creates new user on registration
def create_new_user(email_address):
    password = generate_new_password()
    hashed_password = hash_string(password)
    conn = sqlite3.connect('identifier.sqlite')
    conn.row_factory = dict_factory
    user_id = str(uuid.uuid4())
    try:
        conn = sqlite3.connect('identifier.sqlite')
    except sqlite3.Error as e:
        print(e)
    values = (user_id, email_address.strip().lower().replace(" ", ""), hashed_password.decode('utf-8'), None)
    sql = "INSERT INTO users (id, email, password, activated_at) VALUES(?,?,?,?)"
    curs = conn.cursor()
    curs.execute(sql, values)
    conn.commit()
    conn.close()
    verification_token = generate_account_confirmation_token(
        email_address=email_address.strip().lower().replace(" ", ""), user_id=user_id)
    hashed_email = hash_string(email_address)


# Generates 6 digit verification code
def generate_verification_code():
    code = randint(100000, 999999)  # randint is inclusive at both ends
    return str(code)


# Generates token to reset password
def generate_reset_password_token(electric_mail, user_id, confirmation_code):
    secret = os.getenv("JWT_SECRET")
    encoded = jwt.encode({
        "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=900),
        # "nbf": datetime.datetime.utcnow() + datetime.timedelta(seconds=30),
        "iss": "DarkEngine",
        "aud": ['purpose:reset_password'],
        "sub": {"email": electric_mail, "code": confirmation_code, "user_id": user_id},
        "iat": datetime.datetime.utcnow()
    }, key=secret, algorithm="HS256",
        headers={"kid": str(uuid.uuid5(uuid.NAMESPACE_DNS, electric_mail))})
    return encoded


# Generates token to pass it in url and confirm account
def generate_account_confirmation_token(email_address, user_id):
    phrase = os.getenv('JWT_SECRET')
    encoded = jwt.encode({
        "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=900),
        # "nbf": datetime.datetime.utcnow() + datetime.timedelta(seconds=30),
        "iss": "DarkEngine",
        "aud": ['purpose:activate_account'],
        "sub": {"email": email_address, "user_id": user_id},
        "iat": datetime.datetime.utcnow()
    }, key=phrase,
        algorithm="HS256",
        headers={"kid": str(uuid.uuid5(uuid.NAMESPACE_DNS, email_address))})
    return encoded


# Generates token to change password
def generate_change_password_token(electric_mail, user_id, confirmation_code):
    secret = os.getenv("JWT_SECRET")
    encoded = jwt.encode({
        "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=300),
        # "nbf": datetime.datetime.utcnow() + datetime.timedelta(seconds=30),
        "iss": "DarkEngine",
        "aud": ['purpose:change_password'],
        "sub": {"email": electric_mail, "code": confirmation_code, "user_id": user_id},
        "iat": datetime.datetime.utcnow()
    }, key=secret, algorithm="HS256",
        headers={"kid": str(uuid.uuid5(uuid.NAMESPACE_DNS, electric_mail))})
    return encoded


# Can hash email to pass it to url or password
def hash_string(value):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(bytes(value, encoding="utf-8"), salt)
    return hashed


#  Generates new secured password
def generate_new_password():
    # secure random string
    # secure_str = ''.join((secrets.choice(string.ascii_letters) for i in range(8)))
    # print(secure_str)
    # Output QQkABLyK

    # secure password
    password = ''.join((secrets.choice(string.ascii_letters + string.digits + string.punctuation) for i in range(8)))
    # print(password)
    # output 4x]>@;4)
    return password


# Decode reset password token
def decode_artifacts_for_reset_password(electric_mail, token, code):
    # first check if token is no expired
    # Then define if it's not before
    # After check issuer
    # Extract aud verification code and email
    # Compare if provided encrypted email is same as in sub
    # check that code in sub is same as provided 6 digit code
    phrase = os.getenv('JWT_SECRET')
    try:
        decoded = jwt.decode(token, key=str(phrase), issuer="DarkEngine", audience=['purpose:reset_password'],
                             algorithms=["HS256"])
        # print(decoded)
        if bcrypt.checkpw(password=decoded["sub"]["email"].encode(), hashed_password=electric_mail.encode()):
            # print('Email === hashed email')
            # print(decoded["sub"]["code"])
            if str(decoded["sub"]["code"]) == str(code):
                # print('Code is OK')
                if not decoded["sub"]["user_id"]:
                    return False
                else:
                    # print('USER FOUND')
                    user_id = decoded["sub"]["user_id"]
                    new_password = generate_new_password()
                    # print(new_password)
                    hashed_password = hash_string(new_password)
                    update_password_in_db(user_id=user_id, new_password=hashed_password)
                    return True

            else:
                return False
        else:
            return False
    except BaseException as e:
        print(e)
        return False


# Decode account verification token
def decode_artifacts_for_account_verification(electric_mail, token):
    # decoded = jwt.decode(token, options={"require": ["exp", "iss", "sub"]})
    # print('START ACCOUNT VERIFICATION')
    phrase = os.getenv('JWT_SECRET')
    # print(phrase)
    try:
        decoded = jwt.decode(token, key=str(phrase), issuer="DarkEngine", audience=['purpose:activate_account'],
                             algorithms=["HS256"]
                             )
        # artifact = json.dumps(decoded)
        # print(decoded)
        # for key, value in decoded.items():
        # print(key)
        # print(value)

        if bcrypt.checkpw(password=decoded["sub"]["email"].encode(), hashed_password=electric_mail.encode()):
            activate_user_in_database(decoded["sub"]["user_id"])
            True
        else:
            return False
    except BaseException as e:
        print(e)
        return False


# Decode change password token
def decode_artifacts_for_change_password(electric_mail, token, user_id, code):
    phrase = os.getenv('JWT_SECRET')
    try:
        decoded = jwt.decode(token, key=str(phrase), issuer="DarkEngine",
                             audience=['purpose:change_password'], algorithms=["HS256"])
        if bcrypt.checkpw(password=decoded["sub"]["email"].encode(), hashed_password=electric_mail.encode()):
            if str(decoded["sub"]["code"]) == str(code):
                if not decoded["sub"]["user_id"]:
                    return False
                else:
                    token_user_id = decoded["sub"]["user_id"]
                    if token_user_id == user_id:
                        return True
                    else:
                        return False
            else:
                return False
        else:
            return False
    except BaseException as e:
        print(e)
        return False


# Activate user in database
def activate_user_in_database(user_id):
    conn = sqlite3.connect('identifier.sqlite')
    conn.row_factory = dict_factory
    try:
        conn = sqlite3.connect('identifier.sqlite')
    except sqlite3.Error as e:
        print(e)
    values = (datetime.datetime.now().isoformat(), user_id)
    sql = "UPDATE users SET activated_at=? WHERE id=?"
    curs = conn.cursor()
    curs.execute(sql, values)
    conn.commit()
    conn.close()


# Sets new password for provided user id
def update_password_in_db(user_id, new_password):
    conn = sqlite3.connect('identifier.sqlite')
    conn.row_factory = dict_factory
    try:
        conn = sqlite3.connect('identifier.sqlite')
    except sqlite3.Error as e:
        print(e)
    values = (new_password.decode('utf-8'), user_id)
    sql = "UPDATE users SET password=? WHERE id=?"
    curs = conn.cursor()
    curs.execute(sql, values)
    conn.commit()
    conn.close()


# Checks if provided and hashed passwords match
def is_password_valid(password, hashed_password):
    if bcrypt.checkpw(password=password.encode(), hashed_password=hashed_password.encode()):
        return True
    else:
        return False


@eel.expose
def some_js_function_to_py(function_data):
    print(function_data)


@eel.expose
def pass_python_data_to_js():
    return None


@eel.expose
def get_update(update):
    print(update.data)
    # eel.get_update(update.data)
    return update.data


@eel.expose
def load_recipients_from_database():
    recipients = db.reference('/recipients').get()
    print(recipients)
    return recipients


@eel.expose
def put_recipients_to_database(name, phone):
    print('PUTTING NEW RECIPIENTS')
    recipients = db.reference('/recipients')
    item_id = uuid.uuid5(uuid.NAMESPACE_DNS, 'arabella')
    recipients.set({
        str(item_id): {
            'name': name,
            'phone': phone
        }
    })


@eel.expose
def delete_recipient_from_database():
    return


@eel.expose
def send_sms(message_text, recipients):
    print('SENDING SMS')
    # client = Client(account_sid, auth_token)
    # recipients = load_recipients_from_database()
    # for recipient in recipients:
    #     try:
    #         message = client.messages.create(
    #             to=recipient,
    #             from_="(737) 237-2965",
    #             body=message_text)
    #         time.sleep(1.5)
    #         print(message.sid)
    #         time.sleep(1.5)
    #         print(message.sid)
    #     except:
    #         continue


def initiate_client_local_db():
    client_id = ''
    generated = ''


def init_db():
    # Initialize the app with a None auth variable, limiting the server's access
    firebase_admin.initialize_app(cred, {
        'databaseURL': 'https://eel-client-default-rtdb.firebaseio.com/',
        'databaseAuthVariableOverride': None
    })
    print('init_db')
    # The app only has access to public data as defined in the Security Rules
    db.reference('/detections').listen(get_update)
    # print(ref.get())


init_db()
eel.start('main.html')

# if __name__ == '__main__':
#     init_db()
