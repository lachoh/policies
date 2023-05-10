from flask import render_template, redirect, url_for, request, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user
from . import app, db
from .models import User, Team, Policy, PolicyView
from .forms import LoginForm, RegistrationForm, UploadPolicyForm, AssignPolicyForm
from werkzeug.utils import secure_filename
import os

app.config['UPLOAD_FOLDER'] = 'static/uploads'

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(email=form.email.data, name=form.name.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Query for the current user's policies
    policies = Policy.query.join(Team).filter(Team.id == current_user.team_id).all()
    # Query for the current user's viewed policies
    viewed_policies = PolicyView.query.filter_by(user_id=current_user.id).all()
    viewed_policy_ids = [view.policy_id for view in viewed_policies]

    return render_template('dashboard.html', policies=policies, viewed_policy_ids=viewed_policy_ids)

@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:  # replace with your condition for admin users
        flash('You are not authorized to view this page.', 'danger')
        return redirect(url_for('dashboard'))

    # TODO: Add your admin dashboard functionality
    return render_template('admin.html')

@app.route('/upload_policy', methods=['POST'])
@login_required
def upload_policy():
    if not current_user.is_admin:  # replace with your condition for admin users
        flash('You are not authorized to view this page.', 'danger')
        return redirect(url_for('dashboard'))

    form = UploadPolicyForm()
    if form.validate_on_submit():
        policy_file = form.policy_file.data
        filename = secure_filename(policy_file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        policy_file.save(file_path)

        new_policy = Policy(name=form.policy_name.data, file_path=file_path)
        db.session.add(new_policy)
        db.session.commit()

        flash('Policy uploaded successfully.', 'success')
        return redirect(url_for('admin'))
    return render_template('upload_policy.html', form=form)

@app.route('/assign_policy', methods=['POST'])
@login_required
def assign_policy():
    if not current_user.is_admin:  # replace with your condition for admin users
        flash('You are not authorized to view this page.', 'danger')
        return redirect(url_for('dashboard'))

    form = AssignPolicyForm()
    form.policy.choices = [(policy.id, policy.name) for policy in Policy.query.all()]
    form.team.choices = [(team.id, team.name) for team in Team.query.all()]

    if form.validate_on_submit():
        policy = Policy.query.get(form.policy.data)
        team = Team.query.get(form.team.data)
        policy.team = team
        db.session.commit()
        flash('Policy assigned to team successfully.', 'success')
        return redirect(url_for('admin'))

    return render_template('assign_policy.html', form=form)

@app.route('/view_policy/<int:policy_id>')
@login_required
def view_policy(policy_id):
    policy = Policy.query.get(policy_id)
    if not policy or (current_user.team_id != policy.team_id and not current_user.is_admin):
        flash('You are not authorized to view this policy.', 'danger')
        return redirect(url_for('dashboard'))

    # Register the view
    policy_view = PolicyView(user_id=current_user.id, policy_id=policy_id)
    db.session.add(policy_view)
    db.session.commit()

    return send_from_directory(app.config['UPLOAD_FOLDER'], policy.file_path)

@app.route('/policy_views/<int:policy_id>')
@login_required
def policy_views(policy_id):
    if not current_user.is_admin:  # replace with your condition for admin users
        flash('You are not authorized to view this page.', 'danger')
        return redirect(url_for('dashboard'))

    policy = Policy.query.get(policy_id)
    if not policy:
        flash('Policy not found.', 'danger')
        return redirect(url_for('admin'))

    views = PolicyView.query.filter_by(policy_id=policy_id).all()
    user_views = [(view.user.name, view.timestamp) for view in views]

    return render_template('policy_views.html', user_views=user_views)

