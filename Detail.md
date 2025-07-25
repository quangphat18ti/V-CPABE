# Tài liệu chạy chi tiết.
## Hướng dẫn cài đặt
> Lưu ý: Những cài đặt và chạy này là dành cho mô hình Wat11.
1. Cài đặt môi trường biên dịch ngôn ngữ: Golang.
    - [Hướng dẫn cài đặt - Chính chủ của Golang.](https://go.dev/doc/install)
    - Môi trường Go hiện tại: `go version go1.24.1 darwin/arm64`

2. Build các file binary:
    ```sh
    chmod +x ./run.sh
    ./run.sh build
    ```

## Hướng dẫn chạy
> Lưu ý: Những cài đặt và chạy này là dành cho mô hình Wat11.

### 1. Cấu trúc thư mục chạy
![alt text](image.png)

Đây là cấu trúc mặc định của các file cần thiết để chạy chương trình. Vì vậy, nếu không truyền bất kỳ tham số gì vào các file binary để chạy thì nó sẽ sử dụng các file đã được lưu trữ trong 2 thư mục `/in` và `/out` này.

### 2. Các câu lệnh chạy
Và để dễ chạy chương trình thì tôi đã đóng gói lại thành file `run.sh` để hỗ trợ. Tuy nhiên bạn vẫn có thể sử dụng riêng lẻ từng file `binary` được build ra ở trên để chạy.

Các hướng dẫn để chạy cho từng file thì có thể sử dụng mẫu sau:
```bash
<file binary/ run.sh> -h  # helper
```

Ví dụ file `run.sh`:
```bash
Usage: ./run.sh [command] [arguments]

Commands:
  build                     - Build all tools
  setup [args]              - Run setup with optional arguments
  keygen [args]             - Run key generator with optional arguments
  create-policy [args]      - Convert policy string to JSON format
  encrypt [args]            - Run encryptor with optional arguments
  decrypt [args]            - Run decryption with optional arguments
  verify-key [args]         - Verify key with optional arguments
  verify-ciphertext [args]  - Verify ciphertext with optional arguments
  all                       - Run full demo flow
  clean                     - Clean build artifacts
  help                      - Show this help message

Flags:
  -h, --help                - Show help
  --verbose                 - Enable verbose output

Examples:
  ./run.sh build
  ./run.sh setup -h
  ./run.sh keygen --verbose
  ./run.sh create-policy
  ./run.sh encrypt
  ./run.sh decrypt
  ./run.sh verify-key
  ./run.sh verify-ciphertext
  ./run.sh all

Note: Ensure you have Go installed and your GOPATH is set correctly!
```

#### 1. Setup
Bước đầu tiên của hệ thống, thực hiện khởi tạo các tham số hệ thống và sinh ra cặp khóa Public Key (PK) và Master Secret Key (MSK).

**Cách chạy:**
```bash
# Sử dụng run.sh (khuyên dùng)
./run.sh setup

# Hoặc chạy trực tiếp binary
./bin/setup

# Xem các tùy chọn khả dụng
./bin/setup -h
```

**Các tham số tùy chọn:**
- `-public-key-path`: Đường dẫn lưu Public Key (mặc định: `out/utils/public_key`)
- `-master-secret-key-path`: Đường dẫn lưu Master Secret Key (mặc định: `out/utils/master_secret_key`)
- `-scheme-path`: Đường dẫn file scheme (mặc định: `in/schemes/scheme.json`)
- `-salt`: Giá trị salt cho hashing (mặc định: `default_salt`)
- `-verbose`: Hiển thị thông tin chi tiết

**Ví dụ với tham số tùy chỉnh:**
```bash
./bin/setup -public-key-path "my_keys/pk" -master-secret-key-path "my_keys/msk" -verbose
```

**Output:**
- Public Key được lưu vào `out/utils/public_key`
- Master Secret Key được lưu vào `out/utils/master_secret_key`

#### 2. Keygen
Thực hiện sinh khóa giải mã cho người dùng dựa trên tập thuộc tính của họ. Bước này thường được thực hiện bởi CA (Certificate Authority).

**Cách chạy:**
```bash
# Sử dụng run.sh (khuyên dùng)
./run.sh keygen

# Hoặc chạy trực tiếp binary
./bin/key_generator

# Xem các tùy chọn khả dụng
./bin/key_generator -h
```

**Các tham số tùy chọn:**
- `-attribute-path`: Đường dẫn file chứa thuộc tính người dùng (mặc định: `in/utils/attributes`)
- `-private-key-path`: Đường dẫn lưu private key (mặc định: `out/keys/private_key`)
- `-private-key-proof-path`: Đường dẫn lưu key proof (mặc định: `out/keys/key_proof`)
- `-public-key-path`: Đường dẫn Public Key (mặc định: `out/utils/public_key`)
- `-master-secret-key-path`: Đường dẫn Master Secret Key (mặc định: `out/utils/master_secret_key`)
- `-scheme-path`: Đường dẫn file scheme (mặc định: `in/schemes/scheme.json`)
- `-verbose`: Hiển thị thông tin chi tiết

**Input required:**
- File thuộc tính người dùng tại `in/utils/attributes` (định dạng JSON array):
```json
[
    "teacher",
    "math", 
    "hcmus"
]
```

**Output:**
- Private Key được lưu vào `out/keys/private_key`
- Key Proof được lưu vào `out/keys/key_proof` (để verify tính hợp lệ của key)

#### 3. Encrypt
Thực hiện mã hóa file dữ liệu với một chính sách truy cập (access policy) để tạo ra ciphertext.

**Cách chạy:**
```bash
# Sử dụng run.sh (khuyên dùng)
./run.sh encrypt

# Hoặc chạy trực tiếp binary
./bin/encryptor

# Xem các tùy chọn khả dụng
./bin/encryptor -h
```

**Các tham số tùy chọn:**
- `-input-file-path`: Đường dẫn file cần mã hóa (mặc định: `in/files/input_file.txt`)
- `-access-policy-path`: Đường dẫn file chính sách truy cập (mặc định: `in/utils/access_policy`)
- `-ciphertext-path`: Đường dẫn lưu ciphertext (mặc định: `out/ciphertexts/ciphertext`)
- `-ciphertext-proof-path`: Đường dẫn lưu ciphertext proof (mặc định: `out/ciphertexts/ciphertext_proof`)
- `-public-key-path`: Đường dẫn Public Key (mặc định: `out/utils/public_key`)
- `-scheme-path`: Đường dẫn file scheme (mặc định: `in/schemes/scheme.json`)
- `-verbose`: Hiển thị thông tin chi tiết

**Input required:**
- File dữ liệu cần mã hóa tại `in/files/input_file.txt`
- File chính sách truy cập tại `in/utils/access_policy` (định dạng JSON cây):
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
      "node_type": "OrNode",
      "attribute": "",
      "children": [
        {
          "node_type": "LeafNode",
          "attribute": "teacher", 
          "children": null
        },
        {
          "node_type": "LeafNode",
          "attribute": "student",
          "children": null
        }
      ]
    }
  ]
}
```

**Output:**
- Ciphertext được lưu vào `out/ciphertexts/ciphertext`
- Ciphertext Proof được lưu vào `out/ciphertexts/ciphertext_proof`

#### 4. Verify-Key
Xác minh tính hợp lệ của khóa giải mã mà người dùng nhận được từ CA, kiểm tra xem các thành phần trong khóa có khớp với tập thuộc tính của người dùng hay không.

**Cách chạy:**
```bash
# Sử dụng run.sh (khuyên dùng)
./run.sh verify-key

# Hoặc chạy trực tiếp binary
./bin/decryptor --mode=verify-key

# Với các tham số tùy chỉnh
./bin/decryptor --mode=verify-key -verbose
```

**Các tham số tùy chọn:**
- `-private-key-path`: Đường dẫn private key cần verify (mặc định: `out/keys/private_key`)
- `-private-key-proof-path`: Đường dẫn key proof (mặc định: `out/keys/key_proof`)
- `-attribute-path`: Đường dẫn file thuộc tính (mặc định: `in/utils/attributes`)
- `-public-key-path`: Đường dẫn Public Key (mặc định: `out/utils/public_key`)
- `-scheme-path`: Đường dẫn file scheme (mặc định: `in/schemes/scheme.json`)
- `-verbose`: Hiển thị thông tin chi tiết

**Input required:**
- Private Key từ bước Key Generation
- Key Proof từ bước Key Generation
- File thuộc tính người dùng

**Output:** Kết quả verification (PASS/FAIL) cho biết key có hợp lệ hay không.

#### 5. Verify-Ciphertext
Xác minh tính hợp lệ của ciphertext, kiểm tra xem khóa AES có thực sự được mã hóa đúng theo access policy được công bố hay không.

**Cách chạy:**
```bash
# Sử dụng run.sh (khuyên dùng)
./run.sh verify-ciphertext

# Hoặc chạy trực tiếp binary
./bin/decryptor --mode=verify-ciphertext

# Với các tham số tùy chỉnh
./bin/decryptor --mode=verify-ciphertext -verbose
```

**Các tham số tùy chọn:**
- `-ciphertext-path`: Đường dẫn ciphertext cần verify (mặc định: `out/ciphertexts/ciphertext`)
- `-ciphertext-proof-path`: Đường dẫn ciphertext proof (mặc định: `out/ciphertexts/ciphertext_proof`)
- `-access-policy-path`: Đường dẫn file access policy (mặc định: `in/utils/access_policy`)
- `-public-key-path`: Đường dẫn Public Key (mặc định: `out/utils/public_key`)
- `-scheme-path`: Đường dẫn file scheme (mặc định: `in/schemes/scheme.json`)
- `-verbose`: Hiển thị thông tin chi tiết

**Input required:**
- Ciphertext từ bước Encryption
- Ciphertext Proof từ bước Encryption
- File access policy gốc

**Output:** Kết quả verification (PASS/FAIL) cho biết ciphertext có được mã hóa đúng theo policy hay không.

#### 6. Decrypt
Thực hiện giải mã ciphertext để khôi phục lại file dữ liệu gốc. Người dùng sử dụng private key của mình để giải mã và khôi phục file.

**Cách chạy:**
```bash
# Sử dụng run.sh (khuyên dùng)  
./run.sh decrypt

# Hoặc chạy trực tiếp binary
./bin/decryptor --mode=decrypt

# Với các tham số tùy chỉnh
./bin/decryptor --mode=decrypt -output-path "my_decrypted_file.txt" -verbose
```

**Các tham số tùy chọn:**
- `-ciphertext-path`: Đường dẫn ciphertext cần giải mã (mặc định: `out/ciphertexts/ciphertext`)
- `-private-key-path`: Đường dẫn private key (mặc định: `out/keys/private_key`)
- `-output-path`: Đường dẫn lưu file đã giải mã (mặc định: `out/files/decrypted_file.txt`)
- `-attribute-path`: Đường dẫn file thuộc tính (mặc định: `in/utils/attributes`)
- `-access-policy-path`: Đường dẫn file access policy (mặc định: `in/utils/access_policy`)
- `-public-key-path`: Đường dẫn Public Key (mặc định: `out/utils/public_key`)
- `-scheme-path`: Đường dẫn file scheme (mặc định: `in/schemes/scheme.json`)
- `-verbose`: Hiển thị thông tin chi tiết

**Input required:**
- Ciphertext từ bước Encryption
- Private Key từ bước Key Generation
- File thuộc tính của người dùng

**Output:** File dữ liệu đã được giải mã thành công (nếu thuộc tính của người dùng thỏa mãn access policy).

**Lưu ý:** Chỉ những người dùng có tập thuộc tính thỏa mãn access policy mới có thể giải mã thành công.

#### 7. Create-Policy
Chuyển đổi chính sách truy cập từ định dạng string dễ đọc sang định dạng JSON cây phức tạp mà hệ thống yêu cầu.

**Cách chạy:**
```bash
# Sử dụng run.sh (khuyên dùng)
./run.sh create-policy

# Hoặc chạy trực tiếp binary
./bin/create_policy

# Xem các tùy chọn khả dụng
./bin/create_policy -h
```

**Các tham số tùy chọn:**
- `-policy_path`: Đường dẫn file chứa policy string (mặc định: `in/utils/access_policy_string`)
- `-output`: Đường dẫn lưu file policy JSON (mặc định: `in/utils/access_policy`)

**Ví dụ với tham số tùy chỉnh:**
```bash
./bin/create_policy -policy_path "my_policy.txt" -output "my_output_policy.json"
```

**Input required:**
- File chứa policy string tại `in/utils/access_policy_string`. Ví dụ nội dung:
```
hcmus and (teacher and (physics or math))
```

**Các toán tử được hỗ trợ:**
- `and`: Toán tử AND logic (tất cả điều kiện phải đúng)
- `or`: Toán tử OR logic (ít nhất một điều kiện phải đúng)
- `()`: Nhóm các điều kiện lại với nhau
- Tên thuộc tính: Các string đại diện cho thuộc tính (ví dụ: `teacher`, `student`, `hcmus`, `math`, `physics`)

**Ví dụ các policy string hợp lệ:**
```bash
# Policy đơn giản
"teacher"

# Policy với AND
"teacher and math"

# Policy với OR
"teacher or student"

# Policy phức tạp với nhóm
"hcmus and (teacher and (physics or math))"

# Policy nhiều tầng
"(hcmus or vnu) and (teacher or (student and year2023))"
```

**Output:**
- File JSON policy được lưu vào `in/utils/access_policy` với định dạng cây. Ví dụ:
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

**Lưu ý quan trọng:**
- Policy string phải có syntax đúng, nếu không chương trình sẽ báo lỗi
- Sau khi tạo policy JSON, bạn có thể sử dụng file này trong bước Encrypt
- Đây là bước tùy chọn - bạn có thể tự tạo file JSON theo đúng format hoặc sử dụng tool này để convert từ string