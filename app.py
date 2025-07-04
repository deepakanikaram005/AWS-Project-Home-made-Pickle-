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
feedback_table = None
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
    feedback_table = dynamodb.Table('Feedback')

    use_dynamo = True
except NoCredentialsError:
    print("No AWS credentials found, falling back to local storage.")
except ClientError as e:
    print(f"AWS Client error: {str(e)}")

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
        fullname = request.form.get('fullname')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm = request.form.get('confirm')

        if password != confirm:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('signup'))

        hashed_pw = generate_password_hash(password)

        if use_dynamo:
            existing = users_table.get_item(Key={'email': email}).get('Item')
            if existing:
                flash('Email already registered', 'error')
                return redirect(url_for('signup'))

            users_table.put_item(Item={
                'email': email,
                'fullname': fullname,
                'password': hashed_pw
            })
        else:
            if email in local_users:
                flash('Email already registered', 'error')
                return redirect(url_for('signup'))

            local_users[email] = {
                'email': email,
                'fullname': fullname,
                'password': hashed_pw
            }

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
                sns.publish(
                    TopicArn='arn:aws:sns:ap-south-1:123456789012:YourTopicName',
                    Message=message,
                    Subject='Order Confirmation'
                )
            except ClientError as e:
                print("SNS or DynamoDB error:", e)
        else:
            local_orders.append(order)

        return render_template('success.html', order_id=order_id)

    return render_template('buynow.html')

@app.route('/success/<order_id>')
def success(order_id):
    return render_template('success.html', order_id=order_id)

# -------------------- Feedback Handling --------------------

@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    data = request.get_json()
    feedback_text = data.get('feedback', '').strip()

    if not feedback_text:
        return {'error': 'Empty feedback'}, 400

    feedback_id = str(uuid.uuid4())

    try:
        if use_dynamo:
            feedback_table.put_item(Item={
                'feedback_id': feedback_id,
                'feedback': feedback_text
            })
        else:
            print("Feedback received (local):", feedback_text)
        return {'message': 'Feedback stored successfully'}, 200
    except Exception as e:
        print("Error saving feedback:", e)
        return {'error': str(e)}, 500

# -------------------- Run --------------------

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)



