import os
import zipfile
import shutil
import re
from pathlib import Path
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
EXTRACT_FOLDER = 'extracted'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(EXTRACT_FOLDER, exist_ok=True)

def extract_vulnerable(zip_path, extract_to, root_dir=None):
    extracted_files = []
    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        if not root_dir:
            files = zip_ref.namelist()
            if files and files[0].endswith("/"):
                root_dir = files[0]
            else:
                root_dir = None

        if not root_dir or not root_dir.endswith("/"):
            zip_ref.extractall(extract_to)
            return [os.path.join(extract_to, f) for f in zip_ref.namelist()]

        root_len = len(root_dir)
        for member in zip_ref.infolist():
            filename = member.filename
            if filename == root_dir:
                continue

            path = filename
            if path.startswith(root_dir):
                path = path[root_len:]

            full_path = os.path.join(extract_to, path)
            
            if member.is_dir():
                os.makedirs(full_path, exist_ok=True)
            else:
                os.makedirs(os.path.dirname(full_path), exist_ok=True)
                with open(full_path, "wb") as f:
                    f.write(zip_ref.read(filename))
            extracted_files.append(full_path)
    return extracted_files

def _is_zipinfo_symlink(member: zipfile.ZipInfo) -> bool:
    return (member.external_attr >> 16) & 0o170000 == 0o120000

def extract_secure(zip_path, extract_to, root_dir=None):
    extracted_files = []
    base_dir = Path(extract_to).resolve()
    
    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        members = zip_ref.infolist()
        if not root_dir:
            if members and members[0].filename.endswith("/"):
                root_dir = members[0].filename
            else:
                root_dir = None
        if root_dir:
            root_dir = root_dir.replace("\\", "/")
            if not root_dir.endswith("/"):
                root_dir += "/"

        for member in members:
            if member.flag_bits & 0x1:
                raise RuntimeError(f"Encrypted zip entry not supported: {member.filename}")
            if _is_zipinfo_symlink(member):
                raise RuntimeError(f"Symlink zip entry not supported: {member.filename}")

            name = member.filename.replace("\\", "/")
            if root_dir and name == root_dir:
                continue
            if root_dir and name.startswith(root_dir):
                name = name[len(root_dir) :]
            if not name:
                continue
            
            if name.startswith("/") or name.startswith("//") or re.match(r"^[A-Za-z]:", name):
                raise RuntimeError(f"Unsafe zip path (absolute): {member.filename}")

            parts = [p for p in name.split("/") if p not in ("", ".")]
            
            if any(p == ".." for p in parts):
                raise RuntimeError(f"Unsafe zip path (traversal): {member.filename}")

            rel_path = os.path.join(*parts) if parts else ""
            dest_path = (Path(extract_to) / rel_path).resolve(strict=False)
            
            if dest_path != base_dir and base_dir not in dest_path.parents:
                raise RuntimeError(f"Unsafe zip path (escape): {member.filename}")

            if member.is_dir():
                os.makedirs(dest_path, exist_ok=True)
                continue

            os.makedirs(dest_path.parent, exist_ok=True)
            with zip_ref.open(member) as src, open(dest_path, "wb") as dst:
                shutil.copyfileobj(src, dst)
            
            extracted_files.append(str(dest_path))
            
    return extracted_files

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"status": "error", "message": "No file uploaded"})
    
    file = request.files['file']
    mode = request.form.get('mode')
    
    zip_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(zip_path)

    try:
        if mode == 'secure':
            extracted = extract_secure(zip_path, EXTRACT_FOLDER)
        else:
            extracted = extract_vulnerable(zip_path, EXTRACT_FOLDER)
            
        return jsonify({"status": "success", "files": extracted})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

if __name__ == '__main__':
    app.run(debug=True, port=5000)