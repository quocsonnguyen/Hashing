import os
from flask import Flask, request, render_template
from werkzeug.utils import secure_filename
from Crypto.Hash import SHA1, MD5, SHA256, SHA512, SHA3_256, SHA3_512

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg'}

# flask config
app = Flask(__name__, template_folder="templates", static_folder='assets')
app.config['UPLOAD_FOLDER'] = "/home/quocson/Documents/Hashing/files"
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/api/get_hash_value', methods=["POST"])
def get_hash_value():
    message = request.form["message"]

    hash_type = request.form["hashType"]

    if hash_type == "sha1":
        hash_obj = SHA1.new(message.encode("utf-8"))
        hash_value = hash_obj.hexdigest().upper()
        return {
            "code" : 0,
            "hash_value" : hash_value     
        }

    if hash_type == "md5":
        hash_obj = MD5.new(message.encode("utf-8"))
        hash_value = hash_obj.hexdigest().upper()
        return {
            "code" : 0,
            "hash_value" : hash_value     
        }

    if hash_type == "sha256":
        hash_obj = SHA256.new(message.encode("utf-8"))
        hash_value = hash_obj.hexdigest().upper()
        return {
            "code" : 0,
            "hash_value" : hash_value     
        }

    if hash_type == "sha512":
        hash_obj = SHA512.new(message.encode("utf-8"))
        hash_value = hash_obj.hexdigest().upper()
        return {
            "code" : 0,
            "hash_value" : hash_value     
        }

    if hash_type == "sha3-256":
        hash_obj = SHA3_256.new(message.encode("utf-8"))
        hash_value = hash_obj.hexdigest().upper()
        return {
            "code" : 0,
            "hash_value" : hash_value     
        }

    if hash_type == "sha3-512":
        hash_obj = SHA3_512.new(message.encode("utf-8"))
        hash_value = hash_obj.hexdigest().upper()
        return {
            "code" : 0,
            "hash_value" : hash_value     
        }
    
    return {
        "code" : -1,
        "hash_value" : "Error"     
    }

@app.route('/api/get_file_hash_value', methods=["POST"])
def get_file_hash_value():

    if 'file' not in request.files:
        return {
            "code" : -1,
            "hash_value" : "File not in request"     
        }

    file = request.files['file']
    # if user does not select file, browser also
    # submit an empty part without filename
    if file.filename == '':
        return {
            "code" : -1,
            "hash_value" : "File name is null"     
        }


    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        with open(os.path.join(app.config['UPLOAD_FOLDER'], filename), "rb") as f:
            hash_obj = SHA256.new(f.read())
            hash_value = hash_obj.hexdigest().upper()
            return {
                "code" : 0,
                "hash_value" : hash_value     
            }

    else:
        return {
            "code" : -1,
            "hash_value" : "Not support this type of file"
        }

@app.route('/api/check_integrity', methods=["POST"])
def check_integrity():

    check_sum = request.form.get("checksum")

    if 'file' not in request.files:
        return {
            "code" : -1,
            "hash_value" : "File not in request"     
        }

    file = request.files['file']
    # if user does not select file, browser also
    # submit an empty part without filename
    if file.filename == '':
        return {
            "code" : -1,
            "hash_value" : "File name is null"     
        }


    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        with open(os.path.join(app.config['UPLOAD_FOLDER'], filename), "rb") as f:
            hash_obj = SHA256.new(f.read())
            hash_value = hash_obj.hexdigest().upper()
            if hash_value == check_sum:
                return {
                    "code" : 0,
                    "status" : "That file is data integrity"     
                }
            else:
                return {
                    "code" : -1,
                    "status" : "That file is not data integrity"
                }
            

    else:
        return {
            "code" : -1,
            "hash_value" : "Not support this type of file"
        }
    

if __name__ == '__main__':
    app.run(port="7200", debug=True)