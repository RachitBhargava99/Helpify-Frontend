from flask import Blueprint, render_template, url_for, flash, redirect, request, current_app
from frontend.users.forms import RegistrationForm, LoginForm, RequestResetForm, ResetPasswordForm
from flask_login import login_user, current_user, logout_user, login_required
import requests
import json
from frontend.models import User
from frontend.dashboard.forms import RequestHelpForm


dash = Blueprint('dash', __name__)

@dash.route('/dashboard', methods=['POST', 'GET'])
@login_required
def dashboard():
    request_data = requests.post(current_app.config['ENDPOINT_ROUTE'] + current_app.config['DASHBOARD_URL'],
                         json={
                             'auth_token': current_user.auth_token
                         })
    data = request_data.json()
    if data['status'] == 0:
        flash(data['error'], 'danger')
        logout_user()
        return redirect(url_for('users.login'))
    elif data['status'] == 1:
        if data['user'] == "Normal":
            form = RequestHelpForm()
            if form.validate_on_submit():
                return redirect(url_for('dash.request_help', topic=form.topic.data))
            else:
                return render_template('user_dashboard.html', queue_length=data['queue_length'], helpers_active=data['helpers_active'], estimated_wait_time=int(data['estimated_wait_time']) if type(data['estimated_wait_time']) is not str else "N/A", num_total_sessions=data['num_total_sessions'], current_helpers_active=data['current_helpers_active'], current_wait_time=data['current_wait_time'], current_queue_pos=data['current_queue_pos'], help_requested=data['help_requested'], last_session_date=data['last_session_date'], last_session_topic=data['last_session_topic'], last_session_helper=data['last_session_helper'], form=form)
        elif data['user'] == "Admin":
            if data['activity_status']:
                return render_template('helper_dashboard.html', help_status=data['help_status'], queue_length=data['queue_length'], helpers_active=data['helpers_active'], estimated_wait_time=int(data['estimated_wait_time']) if type(data['estimated_wait_time']) is not str else "N/A", sessions_today=data['sessions_today'], requester_name=data['requester_name'], topic=data['topic'], help_time_left=data['help_time_left'], last_session_date=data['last_session_date'], last_session_topic=data['last_session_topic'], last_session_requester=data['last_session_requester'], activity_status=data['activity_status'], minutes_remaining=data['minutes_remaining'])
            else:
                return render_template('helper_dashboard.html',
                                       queue_length=data['queue_length'], helpers_active=data['helpers_active'],
                                       estimated_wait_time=int(data['estimated_wait_time']) if type(data['estimated_wait_time']) is not str else "N/A",
                                       sessions_today=data['sessions_today'],
                                       last_session_date=data['last_session_date'],
                                       last_session_topic=data['last_session_topic'],
                                       last_session_requester=data['last_session_requester'],
                                       activity_status=data['activity_status'])

@dash.route('/request/<topic>', methods=['POST', 'GET'])
@login_required
def request_help(topic):
    request_data = requests.post(current_app.config['ENDPOINT_ROUTE'] + current_app.config['REQUEST_HELP_URL'],
                                 json={
                                     'auth_token': current_user.auth_token,
                                     'topic': topic
                                 })
    data = request_data.json()
    if data['status'] == 1:
        flash(f"Help request submitted. Please wait for your name to be called.", 'success')
        return redirect(url_for('dash.dashboard'))
    elif data['status'] == 2:
        flash(f"Help request already exists. Please wait for your name to be called.", 'danger')
        return redirect(url_for('dash.dashboard'))
    else:
        flash(f"Sorry, your session has expired. Kindly log in again.")
        return redirect(url_for('users.login'))