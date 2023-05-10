from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, FileField
from wtforms.validators import DataRequired, Email, EqualTo

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class UploadPolicyForm(FlaskForm):
    policy_name = StringField('Policy Name', validators=[DataRequired()])
    policy_file = FileField('Policy File', validators=[DataRequired()])
    submit = SubmitField('Upload')

class AssignPolicyForm(FlaskForm):
    policy = SelectField('Policy', coerce=int)  # Choices to be filled in the view
    team = SelectField('Team', coerce=int)  # Choices to be filled in the view
    submit = SubmitField('Assign')
