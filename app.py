# Import necessary modules
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize Flask app
app = Flask(__name__)
# Set secret key for session management
app.secret_key = 'your_secret_key'  # Replace with a strong secret key 
# Configure SQLAlchemy to use SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
db = SQLAlchemy(app)

# Define User model for the database
class User(db.Model):
    # Define columns for the User table
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# Define Task model for the database
class Task(db.Model):
    # Define columns for the Task table
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_done = db.Column(db.Boolean, default=False)

# Route for the home page
@app.route('/')
def index():
    # Redirect to login page if not logged in
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    # Retrieve tasks for the current user
    user_id = session.get('user_id')
    tasks = Task.query.filter_by(user_id=user_id).all()
    # Render template with tasks
    return render_template('index.html', tasks=tasks)

# Route for user registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    # Handle registration form submission
    if request.method == 'POST':
        # Retrieve username and password from form
        username = request.form['username']
        password = request.form['password']
        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists.')
            return redirect(url_for('register'))
        # Hash password and create new user
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))
    # Render registration form
    return render_template('register.html')

# Route for user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Handle login form submission
    if request.method == 'POST':
        # Retrieve username and password from form
        username = request.form['username']
        password = request.form['password']
        # Query user from database
        user = User.query.filter_by(username=username).first()
        # Check if user exists and password is correct
        if user and check_password_hash(user.password, password):
            # Store user session variables
            session['logged_in'] = True
            session['username'] = user.username
            session['user_id'] = user.id
            flash('You were successfully logged in')
            return redirect(url_for('index'))
        # Flash message for invalid login
        flash('Invalid username or password')
    # Render login form
    return render_template('login.html')

# Route for user logout
@app.route('/logout')
def logout():
    # Clear user session
    session.clear()
    return redirect(url_for('login'))

# Route for admin page
@app.route('/admin')
def admin():
    # Redirect to home if not admin
    if session.get('username') != 'admin':
        return redirect(url_for('index'))
    # Query all users for admin page
    users = User.query.all()
    return render_template('admin.html', users=users)

# Route for deleting a user
@app.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    # Check if current user is admin
    if session.get('username') == 'admin':
        # Query user to delete
        user_to_delete = User.query.get(user_id)
        # Check if user exists and is not admin
        if user_to_delete and user_to_delete.username != 'admin':
            # Delete user from database
            db.session.delete(user_to_delete)
            db.session.commit()
            flash('User deleted successfully')
        else:
            flash('Cannot delete admin user')
        return redirect(url_for('admin'))
    return redirect(url_for('login'))

# Route for adding a task
@app.route('/add_task', methods=['POST'])
def add_task():
    # Redirect to login if not logged in
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    # Create new task for current user
    new_task = Task(title=request.form['title'], user_id=session.get('user_id'))
    db.session.add(new_task)
    db.session.commit()
    return redirect(url_for('index'))

# Route for toggling task completion
@app.route('/toggle_task/<int:task_id>')
def toggle_task(task_id):
    # Check if user is logged in
    if 'logged_in' in session:
        # Query task to toggle
        task = Task.query.get(task_id)
        # Check if task exists and belongs to current user
        if task and task.user_id == session.get('user_id'):
            # Toggle task completion status
            task.is_done = not task.is_done
            db.session.commit()
        return redirect(url_for('index'))
    return redirect(url_for('login'))

# Route for clearing all tasks
@app.route('/clear_tasks')
def clear_tasks():
    # Check if user is logged in
    if session.get('logged_in'):
        # Delete all tasks for current user
        user_id = session.get('user_id')
        Task.query.filter_by(user_id=user_id).delete()
        db.session.commit()
        flash('All tasks cleared!')
    return redirect(url_for('index'))

# Function to setup database
def setup_database(app):
    with app.app_context():
        # Create tables if they do not exist
        db.create_all()
        # Create admin user if not already exists
        if not User.query.filter_by(username='admin').first():
            admin_user = User(username='admin', password=generate_password_hash('admin'))
            db.session.add(admin_user)
            db.session.commit()

# Run the app
if __name__ == '__main__':
    # Setup database and run app in debug mode
    setup_database(app)
    app.run(debug=True)
