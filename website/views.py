from flask import Blueprint, render_template, request, flash, jsonify
from flask_login import login_required, current_user
from .models import Note
from . import db
import json
from website.cryptorithms import encryption as enc
from website.cryptorithms import decryption as dec

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