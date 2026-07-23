# PHỤ LỤC HƯỚNG DẪN SỬ DỤNG
## BẮT ĐẦU VỚI LIBSIGNAL PROTOCOL C (DÀNH CHO NGƯỜI MỚI BẮT ĐẦU)

> [!NOTE]
> Tài liệu này được thiết kế theo dạng **Cầm tay chỉ việc (Step-by-Step)**. Dù bạn chưa từng biên dịch ngôn ngữ C, chưa từng sử dụng CMake hay Visual Studio, bạn vẫn có thể thực hiện thành công từng bước dưới đây.

---

## 1. TỔNG QUAN VỀ DỰ ÁN

**Libsignal Protocol C** là thư viện mã nguồn mở bằng ngôn ngữ C implements giao thức mã hóa đầu-cuối (**End-to-End Encryption**) nổi tiếng của ứng dụng **Signal** (được ứng dụng rộng rãi trong WhatsApp, Facebook Messenger Secret Conversations,...).

Thư viện bao gồm các thuật toán mật mã học cốt lõi:
- **Curve25519 / Ed25519**: Thuật toán đường cong Elliptic để tạo cặp khóa và trao đổi khóa bí mật (ECDH).
- **Double Ratchet Algorithm**: Thuật toán bánh răng kép cuộn khóa liên tục sau mỗi tin nhắn gửi/nhận.
- **HKDF (HMAC-based Key Derivation Function)**: Hàm sinh khóa an toàn từ bí mật chung.
- **Safety Numbers (Fingerprint)**: Tạo mã xác thực số hóa để người dùng tự đối soát độ an toàn của phiên chat.

---

## 2. CHUẨN BỊ MÔI TRƯỜNG (CÀI ĐẶT 1 LẦN DUY NHẤT)

Để biên dịch và chạy code C trên hệ điều hành Windows, máy tính của bạn cần 3 công cụ sau:

| Công cụ | Chức năng | Cách kiểm tra trên máy |
| :--- | :--- | :--- |
| **Visual Studio (MSVC Compiler)** | Trình biên dịch mã C thành file chạy `.exe` | Đã có sẵn trên máy (Windows SDK) |
| **CMake (từ 3.5 trở lên)** | Công cụ quản lý và tự động tạo file cấu hình biên dịch | Đã cài đặt (Phiên bản `4.4.0`) |
| **Visual Studio Code (VS Code)** | Trình soạn thảo giao diện trực quan để xem code & debug | Đã cài đặt |

---

## 3. HƯỚNG DẪN MỞ DỰ ÁN TRÊN VS CODE CHUẨN XÁC

> [!IMPORTANT]
> Việc mở **đúng thư mục gốc chứa mã nguồn** là cực kỳ quan trọng để VS Code nhận diện đúng các đường dẫn thư viện.

1. Khởi động phần mềm **VS Code**.
2. Trên thanh Menu trên cùng: Chọn **File** $\rightarrow$ chọn **Open Folder...** (hoặc nhấn `Ctrl + K` rồi `Ctrl + O`).
3. Điều hướng đến đúng đường dẫn thư mục sau:
   ```text
   E:\M2_Signal\libsignal-protocol-c-master\libsignal-protocol-c-master
   ```
4. Bấm nút **Select Folder**.
5. **Kích hoạt chế độ Tin tưởng (Trust Folder)**:
   - Nếu ở đầu cửa sổ VS Code xuất hiện dải thông báo màu xanh nhạt hoặc hộp thoại *"Do you trust the authors of the files in this folder?"*, hãy nhấn vào nút **Yes, I trust the authors** (hoặc **Trust Folder**).

---

## 4. QUY TRÌNH BIÊN DỊCH VÀ CHẠY CODE TỪ A ĐẾN Z

### Bước 1: Mở cửa sổ Dòng lệnh (Terminal)
Trong màn hình VS Code, nhấn tổ hợp phím **`Ctrl + ~`** (phím tilde bên trái số 1), cửa sổ Terminal sẽ xuất hiện ở phía dưới màn hình.

### Bước 2: Tạo cấu hình dự án bằng CMake
Nhập lệnh sau vào Terminal và nhấn `Enter`:

```powershell
cmake -B build -S . -DBUILD_TESTING=OFF
```

> [!TIP]
> **Giải thích lệnh:**
> - `-B build`: Yêu cầu CMake tạo ra thư mục làm việc riêng tên là `build` để chứa file đầu ra (không làm bẩn thư mục mã nguồn `src`).
> - `-S .`: Chỉ định thư mục chứa mã nguồn hiện tại.
> - `-DBUILD_TESTING=OFF`: Bỏ qua các bộ test mặc định của hệ điều hành Linux để tránh lỗi thiếu thư viện phụ thuộc trên Windows.

Nếu màn hình hiện thông báo `-- Build files have been written to: ...` nghĩa là bạn đã cấu hình thành công!

---

### Bước 3: Biên dịch mã nguồn (Build)
Tiếp tục nhập lệnh sau vào Terminal và nhấn `Enter`:

```powershell
cmake --build build --config Debug
```

> [!TIP]
> **Giải thích lệnh:**
> - Máy tính sẽ tự động tiến hành biên dịch từng file mã C (`curve.c`, `hkdf.c`, `ratchet.c`,...) và liên kết chúng thành file thư viện `signal-protocol-c.lib` cùng file thực thi `demo.exe`.

Màn hình hiển thị `demo.vcxproj -> ...\build\Debug\demo.exe` là biên dịch thành công 100%!

---

### Bước 4: Chạy chương trình kiểm tra thuật toán (Run)
Nhập lệnh sau để chạy file kết quả:

```powershell
.\build\Debug\demo.exe
```

**Màn hình sẽ in ra kết quả kiểm thử các phép toán đường cong Elliptic Curve25519 & XEdDSA:**

```text
=====================================================
  DEMO LIBSIGNAL PROTOCOL C - VERIFYING ALGORITHMS   
=====================================================

[1] Chay kiem tra thuat toan Curve25519 Elliptic Curve...
SHA512 #1 good
SHA512 #2 good
fe_isreduced good
sc_isreduced good
qB == qB good
qB isneutral good
...
XEdDSA sign good
XEdDSA verify #1 good
XEdDSA verify #2 good
    -> THUAT TOAN CURVE25519 CHAY THANH CONG! (Result = 0)

=====================================================
  HOAN THANH CHAY DEMO THUAT TOAN SIGNAL PROTOCOL    
=====================================================
```

---

## 5. HƯỚNG DẪN ĐỌC VÀ CHỈNH SỬA CODE MẪU ĐỂ TỰ HỌC

Để tự viết code thử nghiệm hoặc in ra các giá trị khóa (Public Key / Private Key):

1. Mở file [demo.c](file:///e:/M2_Signal/libsignal-protocol-c-master/libsignal-protocol-c-master/demo.c) nằm ngay ở góc ngoài thư mục dự án.
2. Bạn có thể thêm các câu lệnh in ấn (`printf`) hoặc thay đổi hàm cần chạy.
3. Sau khi chỉnh sửa và lưu file (`Ctrl + S`), bạn chỉ cần chạy lại **2 lệnh ngắn gọn**:
   ```powershell
   cmake --build build --config Debug
   .\build\Debug\demo.exe
   ```

---

## 6. DANH SÁCH TRA CỨU FILE MÃ NGUỒN THUẬT TOÁN

Khi muốn học thuật toán nào, bạn chỉ cần mở file tương ứng trong thư mục `src/`:

- 📜 **[curve.c](file:///e:/M2_Signal/libsignal-protocol-c-master/libsignal-protocol-c-master/src/curve.c)**: Trao đổi khóa Elliptic Curve25519.
- 📜 **[hkdf.c](file:///e:/M2_Signal/libsignal-protocol-c-master/libsignal-protocol-c-master/src/hkdf.c)**: Thuật toán sinh khóa HMAC.
- 📜 **[ratchet.c](file:///e:/M2_Signal/libsignal-protocol-c-master/libsignal-protocol-c-master/src/ratchet.c)**: Thuật toán đổi khóa liên tục Double Ratchet.
- 📜 **[session_cipher.c](file:///e:/M2_Signal/libsignal-protocol-c-master/libsignal-protocol-c-master/src/session_cipher.c)**: Quy trình mã hóa tin nhắn bằng AES-256-CBC + HMAC.
- 📜 **[fingerprint.c](file:///e:/M2_Signal/libsignal-protocol-c-master/libsignal-protocol-c-master/src/fingerprint.c)**: Thuật toán tạo mã Safety Numbers để so sánh người dùng.

---

## 7. CÁC LỖI THƯỜNG GẶP VÀ CÁCH XỬ LÝ (TROUBLESHOOTING)

### Lỗi 1: `Remove-Item` hoặc không tìm thấy file khi gõ lệnh
- **Nguyên nhân**: Bạn gõ sai đường dẫn thư mục hoặc chưa chuyển Terminal về thư mục dự án.
- **Khắc phục**: Chắc chắn rằng đường dẫn hiển thị ở đầu dòng Terminal là:  
  `PS E:\M2_Signal\libsignal-protocol-c-master\libsignal-protocol-c-master>`

### Lỗi 2: VS Code báo *"Restricted Mode"* không cho bấm xem hàm
- **Khắc phục**: Bấm nút **Trust** ở thanh thông báo màu xanh lam phía trên cùng màn hình.

### Lỗi 3: Chạy `.\build\Debug\demo.exe` báo không tìm thấy file
- **Khắc phục**: Bạn chưa chạy lệnh biên dịch `cmake --build build --config Debug`. Hãy chạy lệnh biên dịch trước khi chạy file `.exe`.
