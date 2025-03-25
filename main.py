from flask import Flask, request, jsonify, send_file
from flask_mysqldb import MySQL
import pyotp
import qrcode
import io
import jwt as pyjwt
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os

app = Flask(__name__)

# Configurations (Replace with your actual DB credentials)
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'ecommerce'
app.config['SECRET_KEY'] = 'your_jwt_secret_key'

mysql = MySQL(app)

# Authentication Decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token or not token.startswith("Bearer "):
            return jsonify({'message': 'Token is missing or improperly formatted!'}), 403

        token = token.split("Bearer ")[1]

        try:
            data = pyjwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])

            cur = mysql.connection.cursor()
            cur.execute("SELECT id FROM users WHERE id=%s", (data['user_id'],))
            user = cur.fetchone()
            cur.close()

            if not user:
                return jsonify({'message': 'User not found!'}), 403

        except pyjwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 403
        except pyjwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 403

        return f(*args, **kwargs)

    return decorated

# User Registration
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        username = data['username']
        password = generate_password_hash(data['password'])
        secret = pyotp.random_base32()

        cur = mysql.connection.cursor()

        # Check if the username already exists
        cur.execute("SELECT id FROM users WHERE username=%s", (username,))
        existing_user = cur.fetchone()
        if existing_user:
            cur.close()
            return jsonify({'message': 'Username already exists!'}), 409

        # Insert new user if username is unique
        cur.execute("INSERT INTO users (username, password, twofa_secret) VALUES (%s, %s, %s)",
                    (username, password, secret))
        mysql.connection.commit()
        cur.close()

        return jsonify({'message': 'User registered successfully', '2FA_Secret': secret}), 201
    except Exception as e:
        return jsonify({'message': 'An error occurred during registration'}), 500

# Generate 2FA QR Code
@app.route('/generate-2fa/<username>', methods=['GET'])
def generate_2fa(username):
    cur = mysql.connection.cursor()
    cur.execute("SELECT twofa_secret FROM users WHERE username=%s", (username,))
    user = cur.fetchone()
    cur.close()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    secret = user[0]
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name='Ecommerce_2FA')
    qr = qrcode.make(uri)
    img = io.BytesIO()
    qr.save(img)
    img.seek(0)
    return send_file(img, mimetype='image/png')

# Verify 2FA Code
@app.route('/verify-2fa/<username>', methods=['POST'])
def verify_2fa(username):
    try:
        data = request.json
        if not data or 'code' not in data:
            return jsonify({'message': 'Missing 2FA code'}), 400

        user_code = data.get('code')

        cur = mysql.connection.cursor()
        cur.execute("SELECT twofa_secret FROM users WHERE username=%s", (username,))
        user = cur.fetchone()
        cur.close()

        if not user:
            return jsonify({'message': 'User not found'}), 404

        secret = user[0]
        totp = pyotp.TOTP(secret)

        # Debugging logs (remove after confirming functionality)
        print(f"Stored Secret: {secret}")
        print(f"Received Code: {user_code}")
        print(f"Verification Result: {totp.verify(user_code)}")

        if totp.verify(user_code):
            return jsonify({'message': '2FA verified successfully'}), 200
        else:
            return jsonify({'message': 'Invalid or expired 2FA code'}), 401
    except Exception as e:
        return jsonify({'message': 'An error occurred while verifying 2FA'}), 500

# Login endpoint to authenticate users and generate a JWT token
@app.route('/login', methods=['POST'])
def login():
    try:
        # Get JSON data from the request
        data = request.json
        username = data.get('username')
        password = data.get('password')
        code = data.get('code')

        # Validate input data
        if not username or not password or not code:
            return jsonify({'message': 'Missing username, password, or 2FA code'}), 400

        # Connect to MySQL and fetch user data
        cur = mysql.connection.cursor()
        cur.execute("SELECT id, password, twofa_secret FROM users WHERE username=%s", (username,))
        user = cur.fetchone()
        cur.close()

        # Check if the user exists
        if not user or not check_password_hash(user[1], password):
            return jsonify({'message': 'Invalid username or password'}), 401

        # Verify the Two-Factor Authentication (2FA) code
        totp = pyotp.TOTP(user[2])
        if not totp.verify(code):
            return jsonify({'message': 'Invalid 2FA code'}), 401

        # Generate JWT token
        token = pyjwt.encode(
    {'user_id': user[0], 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=10)},
    app.config['SECRET_KEY'], algorithm='HS256'
)



        # Ensure token is a string
        if isinstance(token, bytes):
            token = token.decode('utf-8')

        return jsonify({'token': token})

    except Exception as e:
        print("Login Error:", str(e))  # Prints the actual error in the terminal
        return jsonify({'message': str(e)}), 500  # Returns the real error message in response


# CRUD Operations for Products
#Add a new product
@app.route('/products', methods=['POST'])
@token_required
def add_product():
    try:
        data = request.json
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO products (name, description, price, quantity) VALUES (%s, %s, %s, %s)",
                    (data['name'], data['description'], data['price'], data['quantity']))
        mysql.connection.commit()
        cur.close()
        return jsonify({'message': 'Product added successfully'}), 201
    except Exception as e:
        return jsonify({'message': 'An error occurred while adding the product'}), 500

# Retrieve a product by its ID
@app.route('/products/<int:product_id>', methods=['GET'])
@token_required
def get_product_by_id(product_id):
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT id, name, description, price, quantity FROM products WHERE id=%s", (product_id,))
        product = cur.fetchone()
        cur.close()

        if not product:
            return jsonify({'message': 'Product not found'}), 404

        # Convert tuple to dictionary
        product_data = {
            'id': product[0],
            'name': product[1],
            'description': product[2],
            'price': product[3],
            'quantity': product[4]
        }

        return jsonify({'product': product_data}), 200
    except Exception as e:
        return jsonify({'message': 'An error occurred while retrieving the product'}), 500

#Retrieve all products
@app.route('/products', methods=['GET'])
@token_required
def get_products():
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT id, name, description, price, quantity FROM products")
        products = cur.fetchall()
        cur.close()

        product_list = [{'id': p[0], 'name': p[1], 'description': p[2], 'price': p[3], 'quantity': p[4]} for p in products]

        return jsonify({'products': product_list}), 200
    except Exception as e:
        return jsonify({'message': 'An error occurred while retrieving products'}), 500
#Update a product by id
@app.route('/products/<int:product_id>', methods=['PUT'])
@token_required
def update_product(product_id):
    try:
        data = request.json
        cur = mysql.connection.cursor()
        cur.execute("UPDATE products SET name=%s, description=%s, price=%s, quantity=%s WHERE id=%s",
                    (data['name'], data['description'], data['price'], data['quantity'], product_id))
        mysql.connection.commit()
        cur.close()
        return jsonify({'message': 'Product updated successfully'}), 200
    except Exception as e:
        return jsonify({'message': 'An error occurred while updating the product'}), 500

#Delete a product by id
@app.route('/products/<int:product_id>', methods=['DELETE'])
@token_required
def delete_product(product_id):
    try:
        cur = mysql.connection.cursor()
        cur.execute("DELETE FROM products WHERE id=%s", (product_id,))
        mysql.connection.commit()
        cur.close()
        return jsonify({'message': 'Product deleted successfully'}), 200
    except Exception as e:
        return jsonify({'message': 'An error occurred while deleting the product'}), 500

if __name__ == '__main__':
    app.run(debug=True)
