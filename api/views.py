from flask import Blueprint, render_template, request, flash, jsonify, redirect, url_for
from flask_login import login_required, current_user
from .models import Data
from . import db
import json
import base64
from .cryptorithms import streamCipher as stc
from .cryptorithms import hashing as has
from .cryptorithms import blockCipher as bcc
from . import app_language, languages


views = Blueprint('views', __name__)

@views.route('/', methods=['GET', 'POST'])
def home1():
    return redirect(url_for('views.home', language=app_language))

@views.route('/<language>', methods=['GET', 'POST'])
@login_required
def home(language):
    if(language not in languages):
        language = app_language
    if request.method == 'POST': 
        plaintext = request.form.get('ptext')
        selecter = request.form.get('enty')
        if len(plaintext) < 1:
            flash('Note is too short!', category='error')
        elif selecter == None:
            flash('No algorithm is selected!', category='error')
        else:
            paraA, paraB = "", ""
            if selecter == "CAESAR_EN":
                paraA = request.form.get("CAESAR_EN_SHIFT")
                ciphertext = stc.caesar_encrypt(plaintext, int(paraA))
            elif selecter == "CAESAR_DE":
                paraA = request.form.get("CAESAR_DE_SHIFT")
                ciphertext = stc.caesar_decrypt(plaintext, int(paraA))  
            elif selecter == "AFFINE_EN":
                paraA = request.form.get("AFFINE_EN_A")
                paraB = request.form.get("AFFINE_EN_B")
                ciphertext = stc.affine_encrypt(plaintext, int(paraA), int(paraB))     
            elif selecter == "AFFINE_DE":
                paraA = request.form.get("AFFINE_DE_A")
                paraB = request.form.get("AFFINE_DE_B")
                ciphertext = stc.affine_decrypt(plaintext, int(paraA), int(paraB))
            elif selecter == "SHA-1":
                ciphertext = has.hash_SHA(plaintext, 1)
            elif selecter == "SHA-256":
                ciphertext = has.hash_SHA(plaintext, 256)
            elif selecter == "SHA-384":
                ciphertext = has.hash_SHA(plaintext, 384)
            elif selecter == "SHA-512":
                ciphertext = has.hash_SHA(plaintext, 512)
            elif selecter == "WHIRLPOOL":
                ciphertext = has.whirlpool_hash(plaintext)
            elif selecter == "BCRYPT":
                ciphertext = has.bcrypt_hash(plaintext)
            elif selecter == "BCRYPT_CHECK":
                paraA = request.form.get("BCRYPT_CHECK_HASH")
                ciphertext = has.bcrypt_check(plaintext, paraA)
                paraB = plaintext
            elif selecter == "CHACHA20_EN":
                ciphertext, paraA, paraB = stc.chacha20_EN(plaintext)
            elif selecter == "CHACHA20_DE":
                paraA = request.form.get("CHACHA20_KEY")
                paraB = request.form.get("CHACHA20_NONCE")
                ciphertext = stc.chacha20_DE(plaintext, paraA, paraB)
            elif selecter == "BLOWFISH_EN":
                ciphertext, paraA = bcc.blowfish_EN(plaintext)
            elif selecter == "BLOWFISH_DE":
                paraA = request.form.get("BLOWFISH_KEY")
                ciphertext = bcc.blowfish_DE(plaintext, paraA)
            elif selecter == "AES-128_CTR_EN":
                password = request.form.get("AES-128-CTR_PASS")
                ciphertext, paraA, paraB = bcc.AES_CTR_EN(plaintext, password, 128)
            elif selecter == "AES-128_CTR_DE":
                paraA = request.form.get("AES-128-CTR_KEY")
                try:
                    paraA = base64.b64decode(paraA)
                    if len(paraA) != 16:
                        flash('Key length must be 16-bytes!', category='error')
                        return render_template("home.html", user=current_user, language=language, **languages[language])
                except:
                    flash('Wrong key format!', category='error')
                    return render_template("home.html", user=current_user, language=language, **languages[language])
                paraB = request.form.get("AES-128-CTR_NONCE")
                ciphertext = bcc.AES_CTR_DE(plaintext, paraA, paraB)
                paraA = request.form.get("AES-128-CTR_KEY")
            elif selecter == "AES-256_CTR_EN":
                password = request.form.get("AES-256-CTR_PASS")
                ciphertext, paraA, paraB = bcc.AES_CTR_EN(plaintext, password, 256)
            elif selecter == "AES-256_CTR_DE":
                paraA = request.form.get("AES-256-CTR_KEY")
                try:
                    paraA = base64.b64decode(paraA)
                    if len(paraA) != 32:
                        flash('Key length must be 32-bytes!', category='error')
                        return render_template("home.html", user=current_user, language=language, **languages[language])
                except:
                    flash('Wrong key format!', category='error')
                    return render_template("home.html", user=current_user, language=language, **languages[language])
                paraB = request.form.get("AES-256-CTR_NONCE")
                ciphertext = bcc.AES_CTR_DE(plaintext, paraA, paraB)
                paraA = request.form.get("AES-256-CTR_KEY")
            if ciphertext == None:
                flash('Wrong credentials, can\'t decode message!', category='error')
                return render_template("home.html", user=current_user, language=language, **languages[language])
            new_data = Data(data=ciphertext, cryptype=selecter, paramA=paraA, paramB=paraB, user_id=current_user.id)
            db.session.add(new_data)
            db.session.commit()
            flash('Securely Transmitted!', category='success')
    return render_template("home.html", user=current_user, language=language, **languages[language])

@views.route('/learning/<language>', methods=['GET', 'POST'])
def learning(language):
    if(language not in languages):
        language = app_language
    return render_template("learning.html", user=current_user, language=language, **languages[language])

@views.route('/learning/caesar/<language>', methods=['GET', 'POST'])
def caesar(language):
    if(language not in languages):
        language = app_language
    return render_template("/learnItems/caesar.html", user=current_user, language=language, **languages[language])

@views.route('/learning/affin/<language>', methods=['GET', 'POST'])
def affin(language):
    if(language not in languages):
        language = app_language
    return render_template("/learnItems/affin.html", user=current_user, language=language, **languages[language])

@views.route('/learning/sha1/<language>', methods=['GET', 'POST'])
def sha1(language):
    if(language not in languages):
        language = app_language
    return render_template("/learnItems/sha1.html", user=current_user, language=language, **languages[language])

@views.route('/learning/sha2/<language>', methods=['GET', 'POST'])
def sha2(language):
    if(language not in languages):
        language = app_language
    return render_template("/learnItems/sha2.html", user=current_user, language=language, **languages[language])

@views.route('/learning/aes/<language>', methods=['GET', 'POST'])
def aes(language):
    if(language not in languages):
        language = app_language
    return render_template("/learnItems/aes.html", user=current_user, language=language, **languages[language])

@views.route('/learning/blowfish/<language>', methods=['GET', 'POST'])
def blowfish(language):
    if(language not in languages):
        language = app_language
    return render_template("/learnItems/blowfish.html", user=current_user, language=language, **languages[language])

@views.route('/learning/chacha/<language>', methods=['GET', 'POST'])
def chacha(language):
    if(language not in languages):
        language = app_language
    return render_template("/learnItems/chacha.html", user=current_user, language=language, **languages[language])

@views.route('/learning/whirlpool/<language>', methods=['GET', 'POST'])
def whirlpool(language):
    if(language not in languages):
        language = app_language
    return render_template("/learnItems/whirlpool.html", user=current_user, language=language, **languages[language])

@views.route('/learning/bcrypt/<language>', methods=['GET', 'POST'])
def bcrypt(language):
    if(language not in languages):
        language = app_language
    return render_template("/learnItems/bcrypt.html", user=current_user, language=language, **languages[language])


@views.route('/delete-data', methods=['POST'])
@login_required
def delete_data():  
    data = json.loads(request.data)
    dataId = data['dataId']
    data = Data.query.get(dataId)
    if data:
        if data.user_id == current_user.id:
            db.session.delete(data)
            db.session.commit()
    return jsonify({})