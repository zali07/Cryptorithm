from flask import Blueprint, render_template, request, flash, jsonify
from flask_login import login_required, current_user
from .models import Note
from . import db
import json
from website.cryptorithms import encryption as enc
from website.cryptorithms import decryption as dec
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
                    ciphertext = enc.caesar_encrypt(plaintext, int(shift))
                case "AFFINE_EN":
                    affine_en_a = request.form.get("AFFINE_EN_A")
                    affine_en_b = request.form.get("AFFINE_EN_B")
                    ciphertext = enc.affine_encrypt(plaintext, int(affine_en_a), int(affine_en_b))
                case "CAESAR_DE":
                    shift = request.form.get("CAESAR_DE_SHIFT")
                    ciphertext = dec.caesar_decrypt(plaintext, int(shift))                
                case "AFFINE_DE":
                    affine_de_a = request.form.get("AFFINE_DE_A")
                    affine_de_b = request.form.get("AFFINE_DE_B")
                    ciphertext = dec.affine_decrypt(plaintext, int(affine_de_a), int(affine_de_b))
                case "SHA-1":
                    ciphertext = has.hash_SHA(plaintext, 1)
                case "SHA-256":
                    ciphertext = has.hash_SHA(plaintext, 256)
                case "SHA-384":
                    ciphertext = has.hash_SHA(plaintext, 384)
                case "SHA-512":
                    ciphertext = has.hash_SHA(plaintext, 512)
                case"AES-128_CTR_EN":
                    password = request.form.get("AES-128-CTR_PASS")
                    ciphertext, salt, key128, nonce = bcm.AES128_CTR_EN(plaintext, password)
                case"AES-128_CTR_DE":
                    salt = request.form.get("AES-128-CTR_PASS")
                    key = request.form.get("AES-128-CTR_PASS")
                    nonce = request.form.get("AES-128-CTR_PASS")
                    ciphertext = bcm.AES128_CTR_DE(plaintext, password)
                case"AES-256_CTR_EN":
                    password = request.form.get("AES-256-CTR_PASS")
                    ciphertext, salt, key256, nonce = bcm.AES256_CTR_EN(plaintext, password)
                case"AES-256_CTR_DE":
                    key = request.form.get("AES-256-CTR_KEY")
                    key = bytes(key, 'utf-8')
                    if len(key) != 32:
                        flash('Key is not 32-byte long! '+str(len(key)), category='error')
                    salt = request.form.get("AES-256-CTR_SALT")
                    nonce = request.form.get("AES-256-CTR_NONCE")
                    # ciphertext = bcm.AES256_CTR_DE(plaintext, password)
                    ciphertext = key

            new_note = Note(data=ciphertext, user_id=current_user.id)
            db.session.add(new_note)
            db.session.commit()
            flash('Securely Transmitted!', category='success')
    return render_template("home.html", user=current_user)

@views.route('/about', methods=['GET', 'POST'])
def about():
    return render_template("about.html", user=current_user)

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