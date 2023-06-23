from flask import Blueprint, render_template, request, flash, jsonify
from flask_login import login_required, current_user
from .models import Data
from . import db
import json
import base64
from .cryptorithms import dataTransformation as dat
from .cryptorithms import hashing as has
from .cryptorithms import blockCipherMode as bcm
from . import app_language, languages


views = Blueprint('views', __name__)

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
            match selecter:
                case "CAESAR_EN":
                    paraA = request.form.get("CAESAR_EN_SHIFT")
                    ciphertext = dat.caesar_encrypt(plaintext, int(paraA))
                case "AFFINE_EN":
                    paraA = request.form.get("AFFINE_EN_A")
                    paraB = request.form.get("AFFINE_EN_B")
                    ciphertext = dat.affine_encrypt(plaintext, int(paraA), int(paraB))
                case "CAESAR_DE":
                    paraA = request.form.get("CAESAR_DE_SHIFT")
                    ciphertext = dat.caesar_decrypt(plaintext, int(paraA))                
                case "AFFINE_DE":
                    paraA = request.form.get("AFFINE_DE_A")
                    paraB = request.form.get("AFFINE_DE_B")
                    ciphertext = dat.affine_decrypt(plaintext, int(paraA), int(paraB))
                case "SHA-1":
                    ciphertext = has.hash_SHA(plaintext, 1)
                case "SHA-256":
                    ciphertext = has.hash_SHA(plaintext, 256)
                case "SHA-384":
                    ciphertext = has.hash_SHA(plaintext, 384)
                case "SHA-512":
                    ciphertext = has.hash_SHA(plaintext, 512)
                case "AES-128_CTR_EN":
                    password = request.form.get("AES-128-CTR_PASS")
                    ciphertext, paraA, paraB = bcm.AES_CTR_EN(plaintext, password, 128)
                case "AES-128_CTR_DE":
                    paraA = request.form.get("AES-128-CTR_KEY")
                    paraA = base64.b64decode(paraA)
                    if len(paraA) != 16:
                        flash('Key length must be 16-bytes!', category='error')
                        return render_template("home.html", user=current_user, language=language, **languages[language])
                    paraB = request.form.get("AES-128-CTR_NONCE")
                    ciphertext = bcm.AES_CTR_DE(plaintext, paraA, paraB)
                    if ciphertext == None:
                        flash('Invalid credentials!', category='error')
                        return render_template("home.html", user=current_user, language=language, **languages[language])
                case "AES-256_CTR_EN":
                    password = request.form.get("AES-256-CTR_PASS")
                    ciphertext, paraA, paraB = bcm.AES_CTR_EN(plaintext, password, 256)
                case "AES-256_CTR_DE":
                    paraA = request.form.get("AES-256-CTR_KEY")
                    paraA = base64.b64decode(paraA)
                    if len(paraA) != 32:
                        flash('Key length must be 32-bytes!', category='error')
                        return render_template("home.html", user=current_user, language=language, **languages[language])
                    paraB = request.form.get("AES-256-CTR_NONCE")
                    ciphertext = bcm.AES_CTR_DE(plaintext, paraA, paraB)
                    if ciphertext == None:
                        flash('Invalid credentials!', category='error')
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