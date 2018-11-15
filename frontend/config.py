import os


class Config:
    SECRET_KEY = '0917b13a9091915d54b6336f45909539cce452b3661b21f386418a257883b30a'
    SQLALCHEMY_DATABASE_URI = os.environ.get('SQLALCHEMY_DATABASE_URI')
    ENDPOINT_ROUTE = 'http://127.0.0.1'
    LOGIN_URL = '/login'
    NORMAL_REGISTER_URL = '/register'
    DASHBOARD_URL = '/dashboard'
    REQUEST_HELP_URL = '/queues/add'
    HELPER_CHECK_IN_URL = '/check_in'
    HELPER_NOT_FOUND_URL = '/queues/not_found'
    HELPER_HELPED_URL = '/queues/modify/helped'
    USER_SESSIONS_URL = '/queues/users/get_session_data'
    HELPER_SESSIONS_URL = '/queues/admin/get_session_data'
    HELPERS_ONLINE_URL = '/users/helpers'