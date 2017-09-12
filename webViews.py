# -*- coding: utf-8 -*-
# import request
from app import app,csrf,login_manager,engine,metadata
from flask import render_template, request, redirect, url_for, flash, abort, g, jsonify, make_response, session
from .forms import RegistrationForm, LoginForm, EmailForm, PasswordForm, CompleteForm
from .models import User, PrivateDetails
from app import db
from flask_login import login_required, current_user, login_user,  logout_user
from .security import generate_confirmation_token, confirm_token,generate_recovery_token,confirm_recovery_token,\
    resend_confirmation_token, confirm_resend_confirmation_token
from .email import send_email
from sqlalchemy.exc import IntegrityError
from functools import wraps






def after_registration(f):
    """This decorator is used to protect the second sign up form after being filled up"""
    @wraps(f)
    def wrap(*args, **kwargs):
        if current_user.account_confirmed is True:
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return wrap

@app.route('/web/gen_tk')
@csrf.exempt
def gen_tk(): 
    try: 
        form=RegistrationForm()
        print form.csrf_token
        return str(form.csrf_token)

    except CSRFError,e:
        return e


@login_manager.user_loader
def user_loader(user_id):
    """ This sets the callback for reloading a user from the session. The
        function you set should take a user ID (a ``unicode``) and return a
        user object, or ``None`` if the user does not exist."""
    return User.query.get(int(user_id))

def complete_registration(f):
    """This decorator is used to ensure that the second sign up form was filled up"""
    @wraps(f)
    def wrap(*args, **kwargs):
        if current_user.account_confirmed is False:
            print "hy"
        else:
            return f(*args, **kwargs)

    return wrap

@app.errorhandler(404)
def page_not_found(e):
    return make_response(jsonify({'error': 'Page not found','code': 404}))
    # return render_template('404.html'), 404


@app.errorhandler(500)
def server_error(e):
    return make_response(jsonify({'error':'Internal server error','code':500}))
    # return render_template('500'.html'), 500

@app.before_request
def before_request():
    g.user = current_user
        

@app.route("/test")
def test():
    session['usr']='cdds'
    return "Hy"
   
def removeOTP(name):
    print name

@app.route('/web/')
# @login_required
# @complete_registration
def w_index():
    
    return jsonify({
        'code': 200,
        'status': 'okays'
        # 'loggedIn':session['usr']
    })



    #  return render_template('index.html')


@app.route('/web/resendMail', methods=['POST'])
@csrf.exempt
def w_resendMail():

    print request.form['email']
    email = User.query.filter_by(email=request.form['email']).first()

    if email is not None and not email.email_confirmed:
        try:

            token = resend_confirmation_token(request.form['email'])
            html = render_template('activate.html', confirm_url='http://127.0.0.1:8000/account/confirMail/'+token,email='http://127.0.0.1:8000/account/resendConfirmation?email='+request.form['email'])

            subject = 'Paymiumm: Confirm Your Account'

            send_email(request.form['email'], subject, html)

            return "true"

        except Exception,e:
            print e
            return "false"
    else:
        print "email not found"
        return "notFound"



@app.route('/web/signup', methods=['POST'])
@csrf.exempt
def w_signup():
        
        try:
            user = User(full_name=request.form['name'], email=request.form['email'], username=request.form['usr'], password=request.form['pwd'],phone_number=request.form['phn'])
            db.session.add(user)
            db.session.commit()
            token = generate_confirmation_token(user.email)

            confirm_url = url_for('confirm_email', token=token, _external=True)

            html = render_template('activate.html', confirm_url='http://127.0.0.1:8000/account/confirMail/'+token,email='http://127.0.0.1:8000/account/resendConfirmation?email='+request.form['email'])

            subject = 'Paymiumm: Confirm Your Account'

            send_email(request.form['email'], subject, html)

            return "true"

        except IntegrityError:
            db.session.rollback()
            return "false"
        except Exception,e:
            db.session.delete(user)
            db.session.commit()
            print "Error Occured: \n"+str(e)
            return "false"




@app.route('/web/complete/signup', methods=['POST'])
@csrf.exempt
def w_complete_signup():
        try:
            # print current_user.account_confirmed

            user = User.query.filter_by(username=request.form['usr'])
            # print user.session.query.filter_by(user.id)
            g.user = PrivateDetails(address=request.form['address'], city=request.form['city'], state=request.form['state'],postal_code=request.form['postalCode'],date_of_birth=request.form['dob'],user_id=str(User.query.get(1)).split(" ")[1])

            user.update(dict(account_confirmed=True))
            db.session.commit()

            db.session.add(g.user)
            db.session.commit()

            print "true"
            return "True"

        except Exception,e:
            print e
            print"false"
            return "False"
    # else:
    #     print "not exisitng"
    #     print "hy"
    #     return "False"



@app.route('/web/confirm/<token>', methods=['GET'])
def w_confirm_email(token):
    """
     the try ... except bit at the beginning to check that the token is valid.
      The token contains a timestamp, so we can tell ts.loads() to raise an exception if it is older than max_age.
      In this case, we’re setting max_age to 86400 seconds, i.e. 24 hours.
    :param token:
    :return:
    """
    try:
        email = confirm_token(token)
        user = User.query.filter_by(email=email).first()
        if user.email_confirmed:
            return "already"
        # flash('Email has already been confirmed Please login')
        else:
            user.email_confirmed = True
            db.session.add(user)
            db.session.commit()
            return user.username
        #  return redirect(url_for('login'))
    except IntegrityError:
        db.session.rollback()
        return "expired"
    except Exception as e:
        return "expired"
        # flash('The confirmation link is invalid or has expired.', 'danger')
        #  abort(404)

 




@app.route('/web/login', methods=['POST'])
@csrf.exempt
def w_login():
            

            user = User.query.filter_by(username=request.form['usr']).first()
            user_mail = User.query.filter_by(email=request.form['usr']).first()

            if user is not None and user.verify_password(request.form['pwd']):

                if user.email_confirmed and user.account_confirmed:

                    # print "\n\n"+request.form['remember']+"\n\n"
                    login_user(user,remember=True)
                    
                    return make_response(jsonify({'res':'true'}))

                    #  return redirect(request.args.get('next') or url_for('index'))
                elif  user.email_confirmed and not user.account_confirmed:

                    login_user(user,remember=True)
                    
                    return make_response(jsonify({'res':'accountUnconfirmed'}))

                return make_response(jsonify({'res':"unconfirmed"}))
                #  flash('Mail not configured')

            elif user_mail is not None and user_mail.verify_password(request.form['pwd']):

                if user_mail.email_confirmed and user_mail.account_confirmed:

                    # print "\n\n"+request.form['remember']+"\n\n"
                    login_user(user_mail,remember=True)
                    


                    return make_response(jsonify({'res':'true'}))
                    #  return redirect(request.args.get('next') or url_for('index'))
                elif  user_mail.email_confirmed and not user_mail.account_confirmed:

                    login_user(user_mail,remember=True)
                    return make_response(jsonify({'res':"accountUnconfirmed"}))

                return make_response(jsonify({'res':"unconfirmed"}))
                #  flash('Mail not configured')

            else:
                return make_response(jsonify({'res':"false"}))
            #  flash('invalid login credentials')
        # return render_template('login.html', form=form)


@app.route('/web/login_', methods=['POST'])
@csrf.exempt
def w_login_():
            
            req_json=request.get_json()
            user = User.query.filter_by(username=req_json['usr']).first()
            user_mail = User.query.filter_by(email=req_json['usr']).first()

            if user is not None and user.verify_password(req_json['pwd']):

                if user.email_confirmed and user.account_confirmed:

                    # print "\n\n"+request.form['remember']+"\n\n"
                    login_user(user,remember=True)
                    
                    return make_response(jsonify({'res':'true'}))

                    #  return redirect(request.args.get('next') or url_for('index'))
                elif  user.email_confirmed and not user.account_confirmed:

                    login_user(user,remember=True)
                    
                    return make_response(jsonify({'res':'accountUnconfirmed'}))

                return make_response(jsonify({'res':"unconfirmed"}))
                #  flash('Mail not configured')

            elif user_mail is not None and user_mail.verify_password(request.form['pwd']):

                if user_mail.email_confirmed and user_mail.account_confirmed:

                    # print "\n\n"+request.form['remember']+"\n\n"
                    login_user(user_mail,remember=True)
                    


                    return make_response(jsonify({'res':'true'}))
                    #  return redirect(request.args.get('next') or url_for('index'))
                elif  user_mail.email_confirmed and not user_mail.account_confirmed:

                    login_user(user_mail,remember=True)
                    return make_response(jsonify({'res':"accountUnconfirmed"}))

                return make_response(jsonify({'res':"unconfirmed"}))
                #  flash('Mail not configured')

            else:
                return make_response(jsonify({'res':"false"}))
            #  flash('invalid login credentials')
        # return render_template('login.html', form=form)


@app.route('/web/reset/password', methods=['POST'])
@csrf.exempt
def w_reset():

    try:
        email=request.form['email']
        # return email
        user = User.query.filter_by(email=request.form['email']).first()

        if user and user.email_confirmed:

            subject = 'Paymiumm: Password reset requested'

            token = generate_recovery_token(user.email)

            # url_for('reset_password_with_token', token=token, _external=True)
            recover_url = "http://127.0.0.1:8000/account/resetMail/"+token

            html = render_template('recover.html', recover_url=recover_url)

            send_email(user.email, subject, html)

            # flash('A confirmation link to reset your password has been sent to you')

            return 'sent'

        else:
            # return 'This Email hasnt been confirmed yet'
            return "ntConfirmed"

    except Exception,e:
        print e
        return "false"

    except IntegrityError,ie:
        print ie
        return "false"




@app.route('/web/reset/<token>', methods=['GET'])
@csrf.exempt
def w_reset_password_with_token(token=""):

    # form = PasswordForm()
        try:
            email = confirm_recovery_token(token)
            return email

        except Exception,e:
            print e
            flash('The confirmation link is invalid or has expired.', 'danger')
            # abort(400)
            return 'x'
    # return render_template('reset_password.html', form=form, token=token)



@app.route('/web/resetMail', methods=['POST'])
@csrf.exempt
def w_reset_password():

        # form = PasswordForm()

        # if form.validate_on_submit():
        print "hy"
        # print request.form['email']
        try:
            user = User.query.filter_by(email=request.form['email']).first()
            user.password = request.form['password']
            db.session.add(user)
            db.session.commit()
            print "changed successfully"
            return "true"

        except IntegrityError,e:
            db.session.rollback()
            print "error"
            print "error at: "+str(e)
            return "false"
        except Exception,e:
            db.session.rollback()

            print "error"
            print "error at: "+str(e)
            return "false"            



@app.route('/web/logout')
@login_required
def w_logout():
    logout_user()
    return jsonify({
        'msg': 'You have been logged out',
        'url': '/web/login'
    })
    # return redirect(url_for('login'))
