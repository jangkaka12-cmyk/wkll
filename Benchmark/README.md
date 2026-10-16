# Benchmark: ECDH và ML-KEM

## Cách chạy

Trong thư mục `P256_MLKEM768`:

```cmd
python -m pip install -r requirements.txt -r Benchmark/requirements.txt
python Benchmark/benchmark.py
```

Nếu máy báo `Python was not found`, hãy gõ `py` thay cho `python`. Chạy hết khoảng 25 giây. Kết quả được ghi vào `Benchmark/ket_qua/`:

| Tệp | Nội dung |
| --- | --- |
| `moi_truong.txt` | CPU, RAM, hệ điều hành, phiên bản Python và cryptography |
| `thi_nghiem_1.csv` | Thời gian, CPU, RAM và kích thước của một lần thiết lập khóa |
| `thi_nghiem_2.csv` | Thời gian gửi + nhận tệp 1 KB → 100 MB, kèm overhead |
| `1_thoi_gian_thiet_lap_khoa.png`, `2_kich_thuoc.png`, `3_truyen_tep.png` | Biểu đồ |

Phần đối chứng bằng thư viện cần bản `cryptography` có module `mlkem`. Máy đo dùng bản 50.0.0.

## Code đo những gì

**Thí nghiệm 1 (một lần thiết lập khóa).** Mọi lược đồ được viết theo cùng 3 bước:

1. `keygen()`: bên nhận tạo cặp khóa rồi gửi khóa công khai cho bên gửi.
2. `encaps(pk)`: bên gửi tạo bí mật chung và gửi lại `ct`. Với ECDH, `ct` là khóa công khai tạm của bên gửi. Với ML-KEM, `ct` là ciphertext.
3. `decaps(sk, ct)`: bên nhận tính ra đúng bí mật chung đó.

Mỗi lần chạy, code `assert` hai bên ra cùng bí mật chung, nên số liệu chỉ được ghi khi thuật toán chạy đúng. Lược đồ được đo bằng hai cách cài đặt:

- **Code nhóm**: Python thuần của Thắng (`ThangV2`), là thứ hệ thống thật đang dùng. ML-KEM-512/1024 dùng hàm nội bộ của `ml_kem.py` với bộ tham số FIPS 203.
- **Thư viện cryptography**: OpenSSL viết bằng C. Đây là mốc đối chứng để tách chi phí của thuật toán khỏi độ chậm của Python. Thư viện không có ML-KEM-512.

**Thí nghiệm 2 (truyền tệp).** Gửi rồi nhận một tệp ngẫu nhiên bằng đúng pipeline của nhóm (`seal_file` / `open_file`, chế độ hybrid P-256 + ML-KEM-768). Thời gian được tách thành 3 phần: thiết lập khóa, mã hóa (bên gửi), giải mã (bên nhận).

**Cách đo:**

| Chỉ số | Cách lấy |
| --- | --- |
| Thời gian | `time.perf_counter()`. Chạy nháp 1 lần, sau đó lặp nhiều lần, lấy trung bình và độ lệch chuẩn |
| CPU | `time.process_time()`, là thời gian CPU tiến trình thật sự dùng |
| RAM | `tracemalloc`, là đỉnh bộ nhớ do Python cấp phát. Không đo được bộ nhớ C bên trong thư viện nên cột này để trống ở các dòng thư viện |

## Kết quả (Ryzen 7 7435HS, Windows 11, Python 3.14)

### Thí nghiệm 1: một lần thiết lập khóa

| Lược đồ | Code nhóm (ms) | Thư viện (ms) | Gửi qua mạng (byte) | Khóa riêng (byte) | RAM code nhóm (KB) |
| --- | --- | --- | --- | --- | --- |
| ECDH P-256 | 47,0 | 0,20 | 66 | 32 | 1,9 |
| ML-KEM-512 | 11,0 | (không có) | 1 568 | 1 632 | 176 |
| ML-KEM-768 | 19,8 | 0,29 | 2 272 | 2 400 | 271 |
| ML-KEM-1024 | 30,9 | 0,43 | 3 136 | 3 168 | 389 |

Mọi lược đồ đều cho bí mật chung dài 32 byte.

### Thí nghiệm 2: gửi + nhận tệp (hybrid)

| Tệp | Tổng (ms) | Thiết lập khóa (ms) | Tỉ lệ thiết lập khóa | Overhead gói tin | RAM đỉnh |
| --- | --- | --- | --- | --- | --- |
| 1 KB | 71 | 70 | 99 % | 398 % | 0,3 MB |
| 1 MB | 93 | 71 | 77 % | 33,7 % | 6,7 MB |
| 10 MB | 242 | 70 | 29 % | 33,4 % | 67 MB |
| 50 MB | 948 | 68 | 7 % | 33,3 % | 333 MB |
| 100 MB | 1 833 | 73 | 4 % | 33,3 % | 667 MB |

### Kết luận

1. **Về tốc độ, chuyển sang ML-KEM không đắt hơn ECDH.**
   - Ở thư viện C, ML-KEM-768 mất 0,29 ms và ECDH mất 0,20 ms, tương đương nhau.
   - Ở code Python của nhóm, ML-KEM còn nhanh hơn ECDH 1,5–4 lần.
2. **Cái giá thật của ML-KEM là kích thước.**
   - Dữ liệu gửi qua mạng: ML-KEM-768 là 2 272 byte, ECDH là 66 byte, tức gấp khoảng 34 lần.
   - Khóa riêng: 2 400 byte so với 32 byte.
   - RAM khi tính: 271 KB so với 2 KB.
3. **Mức bảo mật cao hơn thì tốn hơn.** Từ ML-KEM-512 lên 768 rồi 1024, tham số k tăng từ 2 lên 3 rồi 4 (k là số đa thức trong vector).
   - Kích thước tăng tuyến tính theo k: khóa công khai = 384·k + 32 byte.
   - Thời gian tăng nhanh hơn tuyến tính một chút, vì ma trận A có k×k phần tử.
4. **Thiết lập khóa là chi phí cố định, khoảng 70 ms cho mỗi tệp.**
   - Con số này xấp xỉ ECDH 47 ms cộng ML-KEM-768 20 ms cộng HKDF, khớp với thí nghiệm 1.
   - Với tệp nhỏ, thiết lập khóa chiếm gần hết thời gian. Với tệp 100 MB, nó chỉ còn 4 %, phần còn lại là AES-GCM, SHA-256 và đóng gói JSON.
   - Vì vậy kiến trúc hybrid phù hợp cho truyền tệp.
