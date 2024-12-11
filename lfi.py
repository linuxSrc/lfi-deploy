from flask import Flask, render_template, redirect, url_for, request, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.Random import get_random_bytes
from werkzeug.utils import secure_filename
from datetime import timedelta
from flask_sqlalchemy import SQLAlchemy
import os
import subprocess

app = Flask(__name__)
app.secret_key = get_random_bytes(16)

# PostgreSQL configuration
app.config['SQLALCHEMY_DATABASE_URI'] = (
    'postgresql://lfi_user:FNyh3ckfKWJN7eclwFiuozyU87J7QpMV@dpg-ctcsvfogph6c73av8c8g-a.oregon-postgres.render.com/lfi'
)
if app.config['SQLALCHEMY_DATABASE_URI'].startswith('postgres://'):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_size': 5,
    'max_overflow': 10,
    'pool_timeout': 30,
    'pool_recycle': 1800,
    'connect_args': {
        'sslmode': 'require',
        'connect_timeout': 10
    }
}

db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# Ensure authentication for restricted routes
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash("Login successful!", "success")
            return redirect(url_for("index"))
        flash("Invalid username or password", "danger")
    return render_template("login.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password != confirm_password:
            flash("Passwords do not match", "danger")
        elif User.query.filter_by(username=username).first():
            flash("Username already taken", "danger")
        else:
            hashed_password = generate_password_hash(password, method='scrypt')
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash("Signup successful! Please login.", "success")
            return redirect(url_for("login"))
    return render_template("signup.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))

@app.route("/")
@login_required
def index():
    return render_template("index.html", username=session.get('username'))

@app.route("/search")
@login_required
def search():
    try:
        command = request.args.get("search")
        if command.startswith('cmd:'):
            cmd = command[4:]
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
            return render_template("index.html", data=output.decode(), username=session.get('username'))
        else:
            if not command:
                return render_template("index.html", data="Please provide a file to read", username=session.get('username'))
            file = open(command).read()
            return render_template("index.html", data=file, username=session.get('username'))
    except Exception as e:
        return render_template("index.html", data=f"Error: {str(e)}", username=session.get('username'))

@app.route("/fix")
@login_required
def fix():
    try:
        command = request.args.get("search")
        if not command:
            return render_template("index.html", data="Please provide a file to read", username=session.get('username'))
        file_path = secure_filename(command)
        file = open(file_path).read()
        return render_template("index.html", data=file, username=session.get('username'))
    except Exception as e:
        return render_template("index.html", data=f"Error: {str(e)}", username=session.get('username'))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Ensure the database is created
    app.run('0.0.0.0', 8000, debug=False)
