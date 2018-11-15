from flask import current_app, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, IntegerField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
import requests
import json


class RegistrationForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    gt_id = IntegerField('GeorgiaTech ID', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=
                             [DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=
                                     [DataRequired()])
    submit = SubmitField('Sign Up')

    @staticmethod
    def validate_email(self, email):
        if email.data[-11:] != "@gatech.edu":
            print("checked")
            flash("Enter your GeorgiaTech email address.", 'danger')
            raise ValidationError("Enter your GeorgiaTech email address.")

    @staticmethod
    def validate_password(self, password):
        if len(password.data) < 8:
            flash("Password must be at least eight characters long.", 'danger')
            raise ValidationError("Password must be at least eight characters long.")

    @staticmethod
    def validate_confirm_password(self, password):
        if self.password.data != self.confirm_password.data:
            flash("The passwords do not match.", 'danger')
            raise ValidationError("The passwords do not match.")


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Log In')

    @staticmethod
    def validate_email(self, email):
        if email.data[-11:] != "@gatech.edu":
            print("checked")
            flash("Enter your GeorgiaTech email address.", 'danger')
            raise ValidationError("Enter your GeorgiaTech email address.")


class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Reset Password')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=
    [DataRequired(), Length(min=8, max=32)])
    confirm_password = PasswordField('Confirm Password', validators=
    [DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')
