import base64
import os
import tempfile
from flask import Blueprint, flash, render_template, request, send_file
from encryption import PasswordEncryption
from generator_func import generator_func
from cipher_class import cipher_class
# from stegonography import Steganography
from stegano import lsb
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


views = Blueprint(__name__, "views")


@views.route("/", methods=["GET"])
def home():
    if request.method == "GET":
        return render_template("index.html")


@views.route("/generator", methods=["GET", "POST"])
def generator():
    if request.method == "POST":
        # get values from form
        selected_option = request.form.get("selected_option")
        checked_num = request.form.get("checked_num")
        checked_char = request.form.get("checked_char")
        checked_low = request.form.get("checked_low")
        checked_up = request.form.get("checked_up")
        checked_sym = request.form.get("checked_sym")
        checked_amb = request.form.get("checked_amb")

        # if no length is selected, default to 16
        if selected_option == "":
            selected_option = "16"

        # calling generator function from generator_func.py with values from form
        password = generator_func.generator(
            selected_option, checked_num, checked_char, checked_low, checked_up, checked_sym, checked_amb)

        # return password to user and keeping page persistent
        return render_template("generator.html", password=password, selected_option=selected_option, checked_num=checked_num, checked_char=checked_char, checked_low=checked_low, checked_up=checked_up, checked_sym=checked_sym, checked_amb=checked_amb)

    elif request.method == "GET":
        # default values for generator and generating password
        password = generator_func.generator(
            "16", "on", "on", "on", "on", "on", "on")
        return render_template("generator.html", password=password, selected_option="16", checked_num="on", checked_char="on", checked_low="on", checked_up="on", checked_sym="on", checked_amb="on")


@views.route("/encryptpassword", methods=["GET", "POST"])
def encryptpassword():
    if request.method == "POST":
        # pulling password from form
        password = request.form['password_input']

        # returning encrypted password to user
        return render_template("password_encrypt.html", hashed=PasswordEncryption.encrypt_password(password), password=password)

    elif request.method == "GET":
        return render_template("password_encrypt.html", hashed="Encrypted password will be displayed here", password="Please enter an exxample password")


@views.route("/encryptfile", methods=["GET", "POST"])
def encryptfile():
    if request.method == "POST":
        # checking wether to render the encrypt or decrypt page
        if 'encrypt' in request.form:
            return render_template("file_encrypt.html", page_to_load="encrypt")

        elif 'decrypt' in request.form:
            return render_template("file_encrypt.html", page_to_load="decrypt")

        # code to encrypt file
        elif 'pleaseencrypt' in request.form:
            # getting file and password from form
            uploaded_file = request.files['file_to_encrypt']
            password = request.form['password'].encode('utf-8')

            # setting up encryption
            # please note default salt used for demo to work around having to store salt for each user
            salt = b'thisisasoltformakinglifesimple'
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=480000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password))
            fernet = Fernet(key)

            # creating temp file to store encrypted file
            temp_dir = tempfile.gettempdir()
            os.makedirs(temp_dir, exist_ok=True)
            input_file_path = os.path.join(temp_dir, uploaded_file.filename)
            uploaded_file.save(input_file_path)

            # encrypting the file and wiriting to temp file
            with open(input_file_path, 'rb') as file:
                original = file.read()
            encrypted = fernet.encrypt(original)
            with open(input_file_path, 'wb') as encrypted_file:
                encrypted_file.write(encrypted)

            # returning encrypted file to user
            return send_file(input_file_path, as_attachment=True)

        elif 'pleasedecrypt' in request.form:
            # pulling file and password from form
            uploaded_file = request.files['file_to_encrypt']
            password = request.form['password'].encode('utf-8')

            # setting up decryption
            salt = b'thisisasoltformakinglifesimple'
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=480000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password))
            print(key)
            fernet = Fernet(key)

            # creating temp file to store decrypted file
            temp_dir = tempfile.gettempdir()
            os.makedirs(temp_dir, exist_ok=True)
            input_file_path = os.path.join(temp_dir, uploaded_file.filename)
            uploaded_file.save(input_file_path)

            # decrypting file and writing to temp file
            with open(input_file_path, 'rb') as file:
                original = file.read()
            encrypted = fernet.decrypt(original)
            with open(input_file_path, 'wb') as encrypted_file:
                encrypted_file.write(encrypted)

            # returning decrypted file to user
            return send_file(input_file_path, as_attachment=True)

    elif request.method == "GET":
        return render_template("file_encrypt.html", hashed="Encrypted password will be displayed here", page_to_load="home")


@views.route("/ceasar", methods=["GET", "POST"])
def ceasar():
    if request.method == "POST":
        # getting the shift value and text from the form
        shift = request.form.get("shift_input")
        text = request.form['text_input']

        # returning the page with the encrypted text
        return render_template("ceasar.html", hashed=cipher_class.ceaser(shift, text), shift_value=shift, default_text=text)

    elif request.method == "GET":
        return render_template("ceasar.html", hashed="Encrypted password will be displayed here", shift_value=3, default_text="Please enter the text to be encrypted here")


@views.route("/stego", methods=["GET", "POST"])
def stego():
    if request.method == "POST":
        if 'hide' in request.form:
            # returning the page with the hide section rendered
            return render_template("steganography.html", page_to_load="hide")

        elif 'reveal' in request.form:
            # returning the page with the reveal section rendered
            return render_template("steganography.html", page_to_load="reveal", secret="The secret message will be displayed here")

        elif 'pleasehide' in request.form:
            # pulling the text and file from the form
            text = request.form['text_to_hide']
            uploaded_file = request.files['file_to_hide']

            # saving the file to a temp directory
            temp_dir = tempfile.gettempdir()
            os.makedirs(temp_dir, exist_ok=True)
            input_file_path = os.path.join(temp_dir, uploaded_file.filename)
            uploaded_file.save(input_file_path)

            # hiding the text in the file
            secret = lsb.hide(input_file_path, text)
            output_file_path = os.path.join(temp_dir, "hidden.png")
            secret.save(output_file_path)

            # returning the file to the user
            return send_file(output_file_path, as_attachment=True)

        elif 'pleasereveal' in request.form:
            # pulling the file from the form
            uploaded_file = request.files['file_to_reveal']

            # saving the file to a temp directory
            temp_dir = tempfile.gettempdir()
            os.makedirs(temp_dir, exist_ok=True)
            input_file_path = os.path.join(temp_dir, uploaded_file.filename)
            uploaded_file.save(input_file_path)

            # revealing the text in the file
            secret = lsb.reveal(input_file_path)

            # returning the file to the user
            return render_template("steganography.html", page_to_load="reveal", secret=secret)

    elif request.method == "GET":
        # returning page with the home section rendered
        return render_template("steganography.html", page_to_load="home")


@views.route("/characters", methods=["GET", "POST"])
def characters():
    if request.method == "GET":
        # reuturnin html page
        # all computation done client side
        return render_template("characters.html")


@views.route("/passwordcheck", methods=["GET", "POST"])
def passwordcheck():
    if request.method == "GET":
        # reuturnin html page
        # all computation done client side
        return render_template("password_check.html")
