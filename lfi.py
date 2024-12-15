from flask import Flask, render_template, redirect, url_for, request, session, flash, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.Random import get_random_bytes
from werkzeug.utils import secure_filename
from datetime import timedelta
from flask_sqlalchemy import SQLAlchemy
import os
import subprocess
from dotenv import load_dotenv

load_dotenv()

app=Flask(__name__)
app.secret_key=get_random_bytes(16)

psqlDB = os.getenv('db')

app.config['SQLALCHEMY_DATABASE_URI']=(
    psqlDB
)

if app.config['SQLALCHEMY_DATABASE_URI'].startswith('postgres://'):
    app.config['SQLALCHEMY_DATABASE_URI']=app.config['SQLALCHEMY_DATABASE_URI'].replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
app.config['SQLALCHEMY_ENGINE_OPTIONS']={
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

db=SQLAlchemy(app)

class User(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    username=db.Column(db.String(80), unique=True, nullable=False)
    password=db.Column(db.String(200), nullable=False)

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
        username=request.form['username']
        password=request.form['password']
        user=User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id']=user.id
            session['username']=user.username
            flash("Login successful!", "success")
            return redirect(url_for("index"))
        flash("Invalid username or password", "danger")
    return render_template("login.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username=request.form['username']
        password=request.form['password']
        confirm_password=request.form['confirm_password']
        if password != confirm_password:
            flash("Passwords do not match", "danger")
        elif User.query.filter_by(username=username).first():
            flash("Username already taken", "danger")
        else:
            hashed_password=generate_password_hash(password, method='scrypt')
            new_user=User(username=username, password=hashed_password)
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
    fileP=request.args.get("file")
    if fileP:
        try:
            if not fileP.startswith("static/"):
                file=open(fileP).read()
                return render_template("index.html", data=file, username=session.get('username'))
            return send_file(fileP)  
        except Exception as e:
            return f"Error: {str(e)}", 404
    return render_template("index.html", username=session.get('username'))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()  
    app.run('0.0.0.0', 8000, debug=False)
