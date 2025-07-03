import os
import json
import uuid
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

import boto3
from botocore.exceptions import NoCredentialsError, ClientError

# --- Flask App Setup ---
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'supersecretkey')

# --- AWS Setup ---
use_dynamo = False
sns = None
users_table = None
orders_table = None
local_users = {}
local_orders = []

try:
    session_boto = boto3.Session()
    dynamodb = session_boto.resource('dynamodb', region_name='ap-south-1')
    sns = session_boto.client('sns', region_name='ap-south-1')

    # Test connections
    dynamodb.meta.client.list_tables()
    users_table = dynamodb.Table('Users')
    orders_table = dynamodb.Table('Orders')

    use_dynamo = True
except NoCredentialsError:
    print("No AWS credentials found, falling back to local storage.")
except ClientError as e:
    print(f"AWS Client error: {str(e)}")

# Temporary in-memory store for reset codes
reset_codes = {}

# ------------------- Routes -------------------

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('username')
        password = request.form.get('password')

        user = None
        if use_dynamo:
            user = users_table.get_item(Key={'email': email}).get('Item')
        else:
            user = local_users.get(email)

        if user and check_password_hash(user['password'], password):
            session['user'] = email
            flash('Login successful', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials', 'error')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        hashed_pw = generate_password_hash(password)

        if use_dynamo:
            existing = users_table.get_item(Key={'email': email}).get('Item')
            if existing:
                flash('Email already registered', 'error')
                return redirect(url_for('signup'))

            users_table.put_item(Item={'email': email, 'password': hashed_pw})
        else:
            if email in local_users:
                flash('Email already registered', 'error')
                return redirect(url_for('signup'))
            local_users[email] = {'email': email, 'password': hashed_pw}

        flash('Signup successful. Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You are logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/shop')
def shop():
    return render_template('shop.html')

@app.route('/cart')
def cart():
    return render_template('cart.html')

@app.route('/buynow', methods=['GET', 'POST'])
def buynow():
    if request.method == 'POST':
        if 'user' not in session:
            flash('Please log in first.', 'error')
            return redirect(url_for('login'))

        name = request.form['name']
        phone = request.form['phone']
        address = request.form['address']
        total = request.form['total']

        if not phone.isdigit() or len(phone) != 10:
            flash('Invalid phone number.', 'error')
            return redirect(url_for('buynow'))

        order_id = str(uuid.uuid4())
        email = session['user']

        order = {
            'order_id': order_id,
            'email': email,
            'name': name,
            'phone': phone,
            'address': address,
            'total': total
        }

        if use_dynamo:
            try:
                orders_table.put_item(Item=order)
                message = f"Hi {name}, your order {order_id} is confirmed. Total ₹{total}. Thank you!"
                sns.publish(PhoneNumber='+91' + phone, Message=message)
            except ClientError as e:
                print("SNS or DynamoDB error:", e)
        else:
            local_orders.append(order)

        return render_template('success.html', order_id=order_id)

    return render_template('buynow.html')

@app.route('/success/<order_id>')
def success(order_id):
    return render_template('success.html', order_id=order_id)

# -------------------- Password Reset --------------------

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('resetEmail')

        user = users_table.get_item(Key={'email': email}).get('Item') if use_dynamo else local_users.get(email)

        if not user:
            flash("Email not found.", 'error')
            return redirect(url_for('forgot_password'))

        code = str(uuid.uuid4())[:6].upper()
        reset_codes[email] = code

        message = f"Your Amma Pickles password reset code: {code}"
        try:
            if sns:
                # Replace with your SNS topic or SMS endpoint
                sns.publish(
                    Message=message,
                    Subject="Password Reset",
                    TopicArn=os.getenv("SNS_RESET_TOPIC_ARN")  # or use PhoneNumber
                )
            flash('Reset code sent.', 'info')
        except ClientError as e:
            flash(f"Error sending SNS: {str(e)}", 'error')

        return redirect(url_for('reset_password', email=email))
    return render_template('forgot_password.html')

@app.route('/reset-password/<email>', methods=['GET', 'POST'])
def reset_password(email):
    if request.method == 'POST':
        code = request.form.get('code')
        new_pw = request.form.get('new_password')
        confirm_pw = request.form.get('confirm_password')

        if reset_codes.get(email) != code:
            flash("Invalid code.", 'error')
            return redirect(url_for('reset_password', email=email))

        if new_pw != confirm_pw:
            flash("Passwords do not match.", 'error')
            return redirect(url_for('reset_password', email=email))

        hashed_pw = generate_password_hash(new_pw)
        if use_dynamo:
            users_table.update_item(
                Key={'email': email},
                UpdateExpression='SET password = :p',
                ExpressionAttributeValues={':p': hashed_pw}
            )
        else:
            local_users[email]['password'] = hashed_pw

        reset_codes.pop(email, None)
        flash("Password reset successful.", 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', email=email)

# -------------------- Run --------------------

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

