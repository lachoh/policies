from datetime import datetime
from . import db
from flask_login import UserMixin

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    team_id = db.Column(db.Integer, db.ForeignKey('team.id'))
    views = db.relationship('PolicyView', backref='user', lazy=True)

class Team(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    members = db.relationship('User', backref='team', lazy=True)
    policies = db.relationship('Policy', backref='team', lazy=True)

class Policy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    file_path = db.Column(db.String(200))
    team_id = db.Column(db.Integer, db.ForeignKey('team.id'))
    views = db.relationship('PolicyView', backref='policy', lazy=True)

class PolicyView(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    policy_id = db.Column(db.Integer, db.ForeignKey('policy.id'))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
