from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, make_response, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    tasks = db.relationship('Task', backref='user', lazy=True)

    def get_task_count(self):
        return Task.query.filter_by(user_id=self.id).count()

    def update_profile(self, username=None, password=None):
        if username:
            self.username = username
        if password:
            self.password = generate_password_hash(password, method='sha256')
        db.session.commit()

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    category = db.Column(db.String(50), default="General")
    completed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def mark_as_completed(self):
        self.completed = True
        db.session.commit()

    def mark_as_incomplete(self):
        self.completed = False
        db.session.commit()

    def log_action(self, action):
        print(f"[{datetime.utcnow()}] Task '{self.title}' - {action}")


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=150)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is already taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is already registered. Please use a different one.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class TaskForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(min=1, max=150)])
    description = TextAreaField('Description')
    category = SelectField('Category', choices=[
        ('Work', 'Work'),
        ('Home', 'Home'),
        ('Study', 'Study'),
        ('General', 'General')
    ], default='General')
    submit = SubmitField('Add Task')

class EditTaskForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(min=1, max=150)])
    description = TextAreaField('Description')
    category = SelectField('Category', choices=[
        ('Work', 'Work'),
        ('Home', 'Home'),
        ('Study', 'Study'),
        ('General', 'General')
    ])
    submit = SubmitField('Save Changes')

class ProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=150)])
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[Length(min=6)])
    confirm_new_password = PasswordField('Confirm New Password', validators=[EqualTo('new_password')])
    submit = SubmitField('Update Profile')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login failed. Check your email and password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
@login_required
def home():
    form = TaskForm()
    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('search', '')
    tasks = Task.query.filter_by(user_id=current_user.id)

    if search_query:
        tasks = tasks.filter(Task.title.contains(search_query))

    tasks = tasks.order_by(Task.created_at.desc()).paginate(page=page, per_page=5)

    if form.validate_on_submit():
        new_task = Task(
            title=form.title.data,
            description=form.description.data,
            category=form.category.data,
            user_id=current_user.id
        )
        db.session.add(new_task)
        db.session.commit()
        new_task.log_action("created")
        flash('Task added successfully!', 'success')
        return redirect(url_for('home'))

    return render_template('home.html', tasks=tasks, form=form, search_query=search_query)

@app.route('/delete/<int:task_id>')
@login_required
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        abort(403)
    task.log_action("deleted")
    db.session.delete(task)
    db.session.commit()
    flash('Task deleted successfully!', 'success')
    return redirect(url_for('home'))

@app.route('/complete/<int:task_id>')
@login_required
def complete_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        abort(403)
    task.mark_as_completed()
    task.log_action("marked as completed")
    flash('Task marked as completed!', 'success')
    return redirect(url_for('home'))

@app.route('/incomplete/<int:task_id>')
@login_required
def incomplete_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        abort(403)
    task.mark_as_incomplete()
    task.log_action("marked as incomplete")
    flash('Task marked as incomplete!', 'warning')
    return redirect(url_for('home'))

@app.route('/edit/<int:task_id>', methods=['GET', 'POST'])
@login_required
def edit_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        abort(403)
    form = EditTaskForm(obj=task)
    if form.validate_on_submit():
        task.title = form.title.data
        task.description = form.description.data
        task.category = form.category.data
        db.session.commit()
        task.log_action("updated")
        flash('Task updated successfully!', 'success')
        return redirect(url_for('home'))
    return render_template('edit_task.html', form=form, task=task)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm()
    task_count = current_user.get_task_count()
    if form.validate_on_submit():
        if not check_password_hash(current_user.password, form.current_password.data):
            flash('Incorrect current password.', 'danger')
            return redirect(url_for('profile'))
        username = form.username.data if form.username.data else None
        new_password = form.new_password.data if form.new_password.data else None
        current_user.update_profile(username=username, password=new_password)
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))
    return render_template('profile.html', task_count=task_count, form=form)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

if __name__ == '__main__':
    app.run(debug=True)