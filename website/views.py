from flask import Blueprint, render_template, request, flash, jsonify
from flask_login import login_required, current_user
from .models import Note
from . import db
import json
import base64
from website.cryptorithms import dataTransformation as dat
from website.cryptorithms import hashing as has
from website.cryptorithms import blockCipherMode as bcm

views = Blueprint('views', __name__)


@views.route('/', methods=['GET', 'POST'])
@login_required
def home():
    if request.method == 'POST': 
        plaintext = request.form.get('ptext')
        selecter = request.form.get('enty')
        if len(plaintext) < 1:
            flash('Note is too short!', category='error')
        elif selecter == None:
            flash('No algorithm is selected!', category='error')
        else:
            match selecter:
                case "CAESAR_EN":
                    shift = request.form.get("CAESAR_EN_SHIFT")
                    ciphertext = dat.caesar_encrypt(plaintext, int(shift))
                case "AFFINE_EN":
                    affine_en_a = request.form.get("AFFINE_EN_A")
                    affine_en_b = request.form.get("AFFINE_EN_B")
                    ciphertext = dat.affine_encrypt(plaintext, int(affine_en_a), int(affine_en_b))
                case "CAESAR_DE":
                    shift = request.form.get("CAESAR_DE_SHIFT")
                    ciphertext = dat.caesar_decrypt(plaintext, int(shift))                
                case "AFFINE_DE":
                    affine_de_a = request.form.get("AFFINE_DE_A")
                    affine_de_b = request.form.get("AFFINE_DE_B")
                    ciphertext = dat.affine_decrypt(plaintext, int(affine_de_a), int(affine_de_b))
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
                    ciphertext, key, nonce = bcm.AES_CTR_EN(plaintext, password, 128)
                    ciphertext = ciphertext + "\n:" + key + "\n:" +nonce
                case "AES-128_CTR_DE":
                    key = request.form.get("AES-128-CTR_KEY")
                    key = base64.b64decode(key)
                    if len(key) != 16:
                        flash('Key length must be 16-bytes!', category='error')
                        return render_template("home.html", user=current_user)
                    nonce = request.form.get("AES-128-CTR_NONCE")
                    ciphertext = bcm.AES_CTR_DE(plaintext, key, nonce)
                    if ciphertext == None:
                        flash('Invalid credentials!', category='error')
                        return render_template("home.html", user=current_user)
                case "AES-256_CTR_EN":
                    password = request.form.get("AES-256-CTR_PASS")
                    ciphertext, key, nonce = bcm.AES_CTR_EN(plaintext, password, 256)
                    ciphertext = ciphertext + "\n:" + key + "\n:" +nonce
                case "AES-256_CTR_DE":
                    key = request.form.get("AES-256-CTR_KEY")
                    key = base64.b64decode(key)
                    if len(key) != 32:
                        flash('Key length must be 32-bytes!', category='error')
                        return render_template("home.html", user=current_user)
                    nonce = request.form.get("AES-256-CTR_NONCE")
                    ciphertext = bcm.AES_CTR_DE(plaintext, key, nonce)
                    if ciphertext == None:
                        flash('Invalid credentials!', category='error')
                        return render_template("home.html", user=current_user)
            new_note = Note(data=ciphertext, user_id=current_user.id)
            db.session.add(new_note)
            db.session.commit()
            flash('Securely Transmitted!', category='success')
    return render_template("home.html", user=current_user)

@views.route('/learning', methods=['GET', 'POST'])
def learning():
    return render_template("learning.html", user=current_user)

@views.route('/learning/caesar', methods=['GET', 'POST'])
def caesar():
    return render_template("/learnItems/caesar.html", user=current_user)

@views.route('/learning/affin', methods=['GET', 'POST'])
def affin():
    return render_template("/learnItems/affin.html", user=current_user)

@views.route('/learning/sha1', methods=['GET', 'POST'])
def sha1():
    return render_template("/learnItems/sha1.html", user=current_user)

@views.route('/learning/sha2', methods=['GET', 'POST'])
def sha2():
    return render_template("/learnItems/sha2.html", user=current_user)

@views.route('/learning/aes', methods=['GET', 'POST'])
def aes():
    return render_template("/learnItems/aes.html", user=current_user)

@views.route('/delete-note', methods=['POST'])
def delete_note():  
    note = json.loads(request.data)
    noteId = note['noteId']
    note = Note.query.get(noteId)
    if note:
        if note.user_id == current_user.id:
            db.session.delete(note)
            db.session.commit()
    return jsonify({})