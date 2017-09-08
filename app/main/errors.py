from . import main
from flask import make_response, jsonify
from .. import db

# noinspection PyUnusedLocal

@main.app_errorhandler(404)
def page_not_found(e):
    return make_response(jsonify({'error': 'Page not found'}), 404)
    # return render_template('404.html'), 404


# noinspection PyUnusedLocal
@main.app_errorhandler(500)
def server_error(e):
    db.session.rollback()
    return make_response(jsonify(error='Internal server error'), 500)
    # return render_template('500'.html'), 500


# noinspection PyUnusedLocal
@main.app_errorhandler(400)
def link_error(e):
    return make_response(jsonify(error='This link is broken or has expired'), 400)
