from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a strong secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_done = db.Column(db.Boolean, default=False)

@app.route('/')
def index():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    user_id = session.get('user_id')
    tasks = Task.query.filter_by(user_id=user_id).all()
    return render_template('index.html', tasks=tasks)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists.')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)

        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please login.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['logged_in'] = True
            session['username'] = user.username
            session['user_id'] = user.id
            flash('You were successfully logged in')
            return redirect(url_for('index'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/admin')
def admin():
    if session.get('username') != 'admin':
        return redirect(url_for('index'))
    users = User.query.all()
    return render_template('admin.html', users=users)

@app.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    if session.get('username') == 'admin':
        user_to_delete = User.query.get(user_id)
        if user_to_delete and user_to_delete.username != 'admin':
            db.session.delete(user_to_delete)
            db.session.commit()
            flash('User deleted successfully')
        else:
            flash('Cannot delete admin user')
        return redirect(url_for('admin'))
    return redirect(url_for('login'))

@app.route('/add_task', methods=['POST'])
def add_task():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    new_task = Task(title=request.form['title'], user_id=session.get('user_id'))
    db.session.add(new_task)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/toggle_task/<int:task_id>')
def toggle_task(task_id):
    if 'logged_in' in session:
        task = Task.query.get(task_id)
        if task and task.user_id == session.get('user_id'):
            task.is_done = not task.is_done
            db.session.commit()
        return redirect(url_for('index'))
    return redirect(url_for('login'))

@app.route('/clear_tasks')
def clear_tasks():
    if session.get('logged_in'):
        user_id = session.get('user_id')
        Task.query.filter_by(user_id=user_id).delete()
        db.session.commit()
        flash('All tasks cleared!')
    return redirect(url_for('index'))

def setup_database(app):
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin_user = User(username='admin', password=generate_password_hash('admin'))
            db.session.add(admin_user)
            db.session.commit()

if __name__ == '__main__':
    setup_database(app)
    app.run(debug=True)
