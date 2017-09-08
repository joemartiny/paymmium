from functools import wraps
from flask import render_template, request, redirect, url_for, flash, g, jsonify, abort
from flask_login import login_required, current_user, login_user, logout_user
from sqlalchemy.exc import IntegrityError
from app import db
from app.auth.email import send_email
from app.auth.security import generate_confirmation_token, confirm_token, generate_recovery_token, \
    confirm_recovery_token, \
    resend_confirmation_token, confirm_resend_confirmation_token
from app.models import User, PrivateDetails
from . import web
from ..generate_one_time_pass import generate_one_time_password as gps


def after_registration(f):
    """This decorator is used to protect the second sign up form after being filled up"""

    @wraps(f)
    def wrap(*args, **kwargs):
        if current_user.account_confirmed is True:
            return redirect(url_for('main.index'))
            #  return jsonify({'url': '/'})
        else:
            return f(*args, **kwargs)
    return wrap


def complete_registration(f):
    """This decorator is used to ensure that the second sign up form was filled up"""

    @wraps(f)
    def wrap(*args, **kwargs):

        if current_user.account_confirmed is False:
            return redirect(url_for('auth.web.complete_signup'))
            #  return jsonify({'url': '/'})
        else:
            return f(*args, **kwargs)

    return wrap


# noinspection PyArgumentList,PyArgumentList,PyArgumentList,PyArgumentList,PyArgumentList,PyArgumentList
@web.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
        # jsonify({'url': '/', 'msg': 'you are already login, you cant perform this action'})

    form = 'something'

    if request.method == 'POST':

        if form.validate_on_submit():
            # noinspection PyArgumentList,PyArgumentList,PyArgumentList,PyArgumentList,PyArgumentList,PyArgumentList
            user = User(full_name=request.form['full_name'], email=request.form['email'],
                        username=request.form['username'], password=request.form['password'],
                        email_confirmed=False, account_confirmed=False)
            try:
                db.session.add(user)
                db.session.commit()
            except IntegrityError:
                db.session.rollback()

                #  The following lines of code
                #  is the confirmation email being sent
                #  to the  user

            token = generate_confirmation_token(user.email)

            confirm_url = url_for('auth.confirm_email', token=token, _external=True)
            html = render_template('activate.html', confirm_url=confirm_url)

            subject = 'Please confirm your Email'

            # send_email function was imported from
            #  the email file
            #
            send_email(user.email, subject, html)

            flash('A mail has been sent to you')

            return redirect(url_for('auth.login'))

            #  return jsonify({'code': 200, 'url': '/login'})
            # else:

            # return jsonify({'msg': 'something wrong occurred',  'url': '/signup'})

    return render_template('register.html', form=form)


@auth.route('/complete/signup', methods=['GET', 'POST'])
@login_required
@after_registration
def complete_signup():
    form = CompleteForm(request.form)

    if request.method == 'POST':
        if form.validate_on_submit():
            g.user = PrivateDetails(address=request.form['address'], city=request.form['city'],
                                    state=request.form['state'],
                                    postal_code=request.form['postal_code'], phone_number=request.form['phone_number'],
                                    date_of_birth=request.form['date_of_birth'])

            current_user.account_confirmed = True
            db.session.add(g.user)
            db.session.commit()

            return redirect(url_for('main.index'))

            #  return jsonify({'code': 200,  'url': '/',  'status': 'okay'})

            # else:
            # return jsonify({'url': '/complete/signup',  'status': 'Error ','msg': 'check post data'})

    return render_template('test.html', form=form)


# noinspection PyBroadException
@auth.route('/confirm/<token>')
def confirm_email(token):
    """
     the try ... except bit at the beginning to check that the token is valid.
      The token contains a timestamp, so we can tell ts.loads() to raise an exception if it is older than max_age.
      In this case, we’re setting max_age to 86400 seconds, i.e. 24 hours.
    :param token:
    :return:
    """
    # noinspection PyBroadException
    try:
        email = confirm_token(token)
    except:
        #  return jsonify({'msg': 'The confirmation link is invalid or has expired, danger',
        # 'status': False, 'code': 404})
        flash('The confirmation link is invalid or has expired.', 'danger')
        abort(404)

    user = User.query.filter_by(email=email).first()
    if user.email_confirmed:
        #  return jsonify(message='Email has already benn confirmed please login')
        flash('Email has already been confirmed Please login')
    else:
        user.email_confirmed = True
        db.session.add(user)
        db.session.commit()
        #  return jsonify({'status': True,
        #  'msg': 'Your email has been confirmed',
        #  'url': '/login'})

        return redirect(url_for('auth.login'))

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated and current_user.email_confirmed:
        # return jsonify({ 'msg': 'user already logged in',
        # 'url': '/index'})
        return redirect(url_for('main.index'))

    form = LoginForm(request.form)

    if request.method == 'POST':

        if form.validate_on_submit():

            user = User.query.filter_by(username=request.form['username']).first() or \
                   User.query.filter_by(email=request.form['username']).first()

            if user is not None and user.verify_password(request.form['password']):

                if user.email_confirmed:

                    login_user(user, remember=True)

                    return redirect(request.args.get('next') or url_for('main.index'))

                else:
                    flash('Your email hasnt been verified yet please verify your email to login')

            else:

                flash('invalid login credentials')
                # else:
                # return jsonify({'status': 'Error',# 'msg': 'check post form', # 'url': '/login'})

    return render_template('login.html', form=form)


@auth.route('/resend/email', methods=['GET', 'POST'])
def resend_email():
    if current_user.is_authenticated:
        return jsonify({'url': '/',
                        'msg': 'user already logged in'})

    form = ResendEmailForm(request.form)

    if request.method == 'POST':

        if form.validate_on_submit():

            user = User.query.filter_by(email=request.form['email']).first()

            token = resend_confirmation_token(user.email)

            subject = 'Please confirm your email'

            confirm_url = url_for('auth.confirm_recovery_email', token=token, _external=True)

            html = render_template('resend_email_confirms.html', confirm_url=confirm_url)

            send_email(user.email, subject, html)

            flash('A confirmation email has been sent to you')

            return redirect(url_for('main.index'))

            # return jsonify({'url': '/login'})

            # else:

            # return jsonify({'status': 'error','msg': 'check post form',
            # 'url': '/resend/email'})

    return render_template('resend_email.html', form=form)


# noinspection PyUnusedLocal,PyBroadException
@auth.route('/confirm/resend-email/<token>')
def confirm_recovery_email(token):
    # noinspection PyUnusedLocal,PyBroadException
    try:
        email = confirm_resend_confirmation_token(token)
    except Exception as e:
        flash('The confirmation link is invalid or has expired, danger')
        abort(400)
        # return jsonify({'msg': 'The confirmation link is invalid or has expired, danger',
        # 'status': False,'code': 400 })

    user = User.query.filter_by(email=email).first()
    if user.email_confirmed:
        flash('Email has already benn confirmed please login')
        # return jsonify(message='Email has already benn confirmed please login')
    else:
        user.email_confirmed = True
        db.session.add(user)
        db.session.commit()
        # return jsonify({'status': True,
        # 'msg': 'Your email has been confirmed','url': '/login'
        # })
        return redirect(url_for('auth.app.login'))


@auth.route('/reset/password', methods=['GET', 'POST'])
def reset():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    form = EmailForm(request.form)

    if request.method == 'POST':

        if form.validate_on_submit():

            user = User.query.filter_by(email=request.form['email']).first()

            if user and user.email_confirmed:

                subject = 'Password reset requested'

                token = generate_recovery_token(user.email)

                recover_url = url_for('auth.reset_password_with_token', token=token, _external=True)

                html = render_template('recover.html', recover_url=recover_url)

                send_email(user.email, subject, html)

                flash('A confirmation link to reset your password has been sent to you')

                return redirect(url_for('auth.login'))

                # return jsonify({'url': '/login'})

            else:
                flash('This email has\nt been confirmed yet')
                # return jsonify({'msg': 'This email has\nt been confirmed yet'})

    return render_template('reset.html', form=form)


# noinspection PyUnusedLocal,PyBroadException
@auth.route('/reset/<token>', methods=['GET', 'POST'])
def reset_password_with_token(token):
    # noinspection PyBroadException
    try:
        # noinspection PyUnusedLocal
        email = confirm_recovery_token(token)

    except:
        flash('The confirmation link is invalid or has expired, danger')
        abort(400)
        # return jsonify({'msg': 'The confirmation link is invalid or has expired, danger',
        # 'status': False, 'code': 400})

    form = PasswordForm(request.form)

    if request.method == 'POST':

        if form.validate_on_submit():
            user = User.query.filter_by(email=request.form['email']).first()
            user.password = request.form['password']

            db.session.add(user)
            db.session.commit()
            return redirect(url_for('login'))
            #  return jsonify({'url': '/login'})
    return render_template('reset_password.html', form=form, token=token)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    # return jsonify({ 'msg': 'You have been logged out',
    # 'url': url_for('login')})
    return redirect(url_for('auth.web.login'))
