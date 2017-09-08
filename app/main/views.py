from . import main
from flask_login import login_required
from ..auth.app.views import complete_registration
from flask import render_template


@main.route('/')
@login_required
@complete_registration
def index():
    #  return jsonify({'code': 200, 'status': 'okay'})

    return render_template('index.html')
