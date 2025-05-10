from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Use a strong secret key in production

# -------------------- Database Setup --------------------
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# -------------------- Models --------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"

class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    car_model = db.Column(db.String(120), nullable=False)
    date = db.Column(db.String(120), nullable=False)
    time = db.Column(db.String(120), nullable=False)

    user = db.relationship('User', backref=db.backref('bookings', lazy=True))

    def __repr__(self):
        return f"Booking('{self.car_model}', '{self.date}', '{self.time}')"

# -------------------- Routes --------------------
@app.route('/')
def landing():
    return render_template('welcome.html')

@app.route('/login', methods=['POST'])
def login():
    identifier = request.form['username']
    password = request.form['password']

    user = User.query.filter(or_(User.username == identifier, User.email == identifier)).first()

    if user and check_password_hash(user.password, password):
        session['username'] = user.username
        flash("Login successful!", "success")
        return redirect(url_for('dashboard'))
    else:
        flash("Invalid username/email or password. Please try again.", "error")
        return redirect(url_for('landing'))

@app.route('/signup', methods=['POST'])
def signup():
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']

    if not username or not email or not password:
        flash("All fields are required.", "error")
        return redirect(url_for('landing'))

    existing_user = User.query.filter(
        or_(User.username == username, User.email == email)
    ).first()

    if existing_user:
        flash("Username or email already taken.", "error")
        return redirect(url_for('landing'))

    hashed_password = generate_password_hash(password)
    new_user = User(username=username, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    flash("Account created successfully! Please log in.", "success")
    return redirect(url_for('landing'))

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        flash("Please log in first.", "error")
        return redirect(url_for('landing'))
    return render_template('dashboard.html', username=session['username'])

@app.route('/book', methods=['GET', 'POST'])
def book():
    if 'username' not in session:
        flash("You must be logged in to book an appointment.", "error")
        return redirect(url_for('landing'))

    if request.method == 'POST':
        car_model = request.form['car_model']
        date = request.form['date']
        time = request.form['time']

        user = User.query.filter_by(username=session['username']).first()
        new_booking = Booking(car_model=car_model, date=date, time=time, user_id=user.id)

        db.session.add(new_booking)
        db.session.commit()

        flash(f"Booking confirmed for {car_model} on {date} at {time}.", "success")
        return redirect(url_for('my_bookings'))

    return render_template('book.html')

@app.route('/my-bookings')
def my_bookings():
    if 'username' not in session:
        flash("You must be logged in to view bookings.", "error")
        return redirect(url_for('landing'))

    user = User.query.filter_by(username=session['username']).first()
    bookings = Booking.query.filter_by(user_id=user.id).all()

    return render_template('my_bookings.html', bookings=bookings)

@app.route('/my-account', methods=['GET', 'POST'])
def my_account():
    if 'username' not in session:
        flash("You must be logged in to view account details.", "error")
        return redirect(url_for('landing'))

    user = User.query.filter_by(username=session['username']).first()

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password and new_password == confirm_password:
            user.password = generate_password_hash(new_password)
            db.session.commit()
            flash("Password updated successfully!", "success")
        else:
            flash("Passwords do not match or are empty. Please try again.", "error")

    return render_template('my_account.html', user=user)

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash("You have been logged out.", "success")
    return redirect(url_for('landing'))

# -------------------- Run App --------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
