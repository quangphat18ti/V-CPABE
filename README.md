
# 🔐 Verifiable CP-ABE

Một hệ thống mã hóa dựa trên thuộc tính **(CP-ABE)** có thể xác minh được, cho phép người dùng:

- ✅ **Xác minh tính hợp lệ** của khóa giải mã
- 🚫 Không cần **tin tưởng tuyệt đối** vào bên thứ ba
- 🧠 Tích hợp logic verifiable vào các scheme nền như [BSW07](https://www.cs.utexas.edu/~bwaters/publications/papers/cp-abe.pdf) và [Waters11](https://eprint.iacr.org/2008/290.pdf)

---

## 🧭 Hệ Thống Gồm Các Phase:

| Phase | Vai trò | Mô tả |
|-------|---------|-------|
| `1. Setup` | 🔧 Khởi tạo | Sinh ra `PK` và `MSK` |
| `2. KeyGen` | 🛠️ CA thực hiện | Tạo khóa giải mã dựa trên thuộc tính |
| `3. Key Verification` | ✅ Người dùng | Xác minh khóa được cấp đúng |
| `4. Encrypt` | 🔐 Mã hoá | Mã hoá file theo access policy |
| `5. Ciphertext Verification` | 🔍 Kiểm tra | Đảm bảo ciphertext khớp policy |
| `6. Decrypt` | 🔓 Giải mã | Người dùng dùng key để giải mã |
| `7. Policy Create` | 🧱 Tool phụ | Chuyển string policy → JSON tree |

---

## 🧱 Phân Tách Module (4 Binary):

| File binary | Vai trò | Ghi chú |
|-------------|---------|--------|
| `setup` | Sinh khóa hệ thống | Sinh PK + MSK |
| `key_generator` | CA cấp key | Sinh user key + proof |
| `encryptor` | Mã hoá file | Kèm theo access policy |
| `decryptor` | Người dùng | Gồm: `verify-key`, `verify-ciphertext`, `decrypt` |

---

## ⚙️ Cài Đặt

```bash
# Cài Go (nếu chưa)
go version  # yêu cầu >= go1.24.1

# Build các binary
chmod +x ./run.sh
./run.sh build
```

---

## 🚀 Hướng Dẫn Sử Dụng

### 📁 Cấu Trúc Thư Mục Mặc Định

```
project/
├── bin/
├── in/
│   ├── files/
│   └── schemes/
│   └── utils/
├── out/
│   ├── files/
│   ├── keys/
│   ├── utils/
│   └── ciphertexts/
├── run.sh
```

Chi tiết lưu trữ dữ liệu mặc định trong folder `/in` và `/out`:
![alt text](image.png)

---

## 🧪 Các Lệnh Sử Dụng Nhanh

```bash
./run.sh [command] [args]
```

### ✅ Các `command` phổ biến:

| Command | Mô tả |
|---------|-------|
| `build` | Build toàn bộ binary |
| `setup` | Setup hệ thống |
| `keygen` | Sinh khóa người dùng |
| `encrypt` | Mã hóa dữ liệu |
| `decrypt` | Giải mã dữ liệu |
| `verify-key` | Xác minh khóa |
| `verify-ciphertext` | Xác minh ciphertext |
| `create-policy` | Tạo access policy JSON |
| `all` | Chạy toàn bộ flow |
| `clean` | Xoá build artifacts |

---

## 🛠️ Chi Tiết Từng Thành Phần

### 1. Setup (🔧)

```bash
./run.sh setup
./bin/setup -h  # helper
```

- **Output**:
    - `out/utils/public_key`
    - `out/utils/master_secret_key`

---

### 2. Key Generation (🔐)

```bash
./run.sh keygen
./bin/key_generator -h
```

- **Input**:
    - `in/utils/attributes`
- **Output**:
    - `out/keys/private_key`
    - `out/keys/key_proof`

---

### 3. Encrypt (🛡️)

```bash
./run.sh encrypt
./bin/encryptor -h
```

- **Input**:
    - `in/files/input_file.txt`
    - `in/utils/access_policy` (JSON)
- **Output**:
    - `out/ciphertexts/ciphertext`
    - `out/ciphertexts/ciphertext_proof`

---

### 4. Verify Key (🧾)

```bash
./run.sh verify-key
./bin/decryptor --mode=verify-key
```

- **Output**:
    - `PASS` / `FAIL`

---

### 5. Verify Ciphertext (🔍)

```bash
./run.sh verify-ciphertext
./bin/decryptor --mode=verify-ciphertext
```

- **Output**:
    - `PASS` / `FAIL`

---

### 6. Decrypt (🔓)

```bash
./run.sh decrypt
./bin/decryptor --mode=decrypt
```

- **Output**:
    - `out/files/decrypted_file.txt`

---

### 7. Create Policy Tool (🌲)

```bash
./run.sh create-policy
./bin/create_policy -h
```

- **Input**: `access_policy_string`
  ```text
  hcmus and (teacher and (physics or math))
  ```

- **Output**: JSON policy tree tại `in/utils/access_policy`

---

## 📌 Example Policy JSON Output

```json
{
  "node_type": "AndNode",
  "attribute": "",
  "children": [
    {
      "node_type": "LeafNode",
      "attribute": "hcmus",
      "children": null
    },
    {
      "node_type": "AndNode",
      "attribute": "",
      "children": [
        {
          "node_type": "LeafNode",
          "attribute": "teacher",
          "children": null
        },
        {
          "node_type": "OrNode",
          "attribute": "",
          "children": [
            {
              "node_type": "LeafNode",
              "attribute": "physics",
              "children": null
            },
            {
              "node_type": "LeafNode",
              "attribute": "math",
              "children": null
            }
          ]
        }
      ]
    }
  ]
}
```

---

### 📎 Lưu ý

- Các policy string cần đúng format: `and`, `or`, `()`, và không dấu `"`
- Tên thuộc tính phân biệt chữ hoa/thường
- Nên dùng `run.sh` để tránh quên argument
