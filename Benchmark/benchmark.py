"""Benchmark CryptoShield: so sánh ECDH với ML-KEM.

Thí nghiệm 1 - một lần thiết lập khóa: ECDH P-256 và ML-KEM-512/768/1024.
    Đo thời gian từng bước, CPU, RAM và số byte phải gửi qua mạng.
Thí nghiệm 2 - gửi + nhận tệp thật bằng pipeline của nhóm (hybrid P-256 + ML-KEM-768).
    Tách thời gian thiết lập khóa và thời gian mã hóa/giải mã theo kích thước tệp.

Chạy trong thư mục P256_MLKEM768:   python Benchmark/benchmark.py
Kết quả: Benchmark/ket_qua/ (2 file CSV, 3 biểu đồ PNG, moi_truong.txt)
"""

import csv
import os
import platform
import secrets
import statistics
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path

import cryptography
import matplotlib
matplotlib.use("Agg")  # chỉ lưu ảnh, không mở cửa sổ
import matplotlib.pyplot as plt
import psutil
from cryptography.hazmat.primitives.asymmetric import ec, mlkem
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # để import code của Thắng và Tân
from ThangV2 import classical_kex, hybrid_kex, ml_kem
from Encryp_Package.package import dec_package
from Encryp_Package.pipeline import open_file, seal_file
from Encryp_Package.signature import gen_ecdsa_key

OUT = Path(__file__).with_name("ket_qua")
NHOM, THU_VIEN = "Code nhóm (Python)", "Thư viện cryptography (C)"

# ml_kem.py của Thắng chỉ khai báo bộ 768; bộ 512 và 1024 lấy theo bảng tham số FIPS 203.
ML_KEM_512 = ml_kem.MLKEMParameters("ML-KEM-512", k=2, eta1=3, eta2=2, du=10, dv=4,
                                    public_key_bytes=800, private_key_bytes=1632, ciphertext_bytes=768)
ML_KEM_1024 = ml_kem.MLKEMParameters("ML-KEM-1024", k=4, eta1=2, eta2=2, du=11, dv=5,
                                     public_key_bytes=1568, private_key_bytes=3168, ciphertext_bytes=1568)


# ------------------------------------------------------------------ các lược đồ cần so sánh
# Lược đồ nào cũng viết theo cùng khuôn 3 bước, giống luồng gửi tệp:
#   keygen()        bên nhận tạo cặp khóa (pk, sk), gửi pk cho bên gửi
#   encaps(pk)      bên gửi tạo bí mật chung + dữ liệu ct gửi lại cho bên nhận
#   decaps(sk, ct)  bên nhận dùng sk và ct tính ra đúng bí mật chung đó
# ECDH: ct là khóa công khai tạm của bên gửi.  ML-KEM: ct là ciphertext.

def ecdh_nhom():
    def keygen():
        kp = classical_kex.generate_keypair()
        return kp.public_key, kp.private_key

    def encaps(pk):
        tam = classical_kex.generate_keypair()
        return tam.public_key, classical_kex.derive_shared_secret(tam.private_key, pk)

    def decaps(sk, ct):
        return classical_kex.derive_shared_secret(sk, ct)
    return keygen, encaps, decaps


def ml_kem_nhom(p):
    def keygen():
        kp = ml_kem._ml_kem_keygen_internal(p, secrets.token_bytes(32), secrets.token_bytes(32))
        return kp.public_key, kp.private_key

    def encaps(pk):
        kq = ml_kem._ml_kem_encaps_internal(p, pk, secrets.token_bytes(32))
        return kq.ciphertext, kq.shared_secret

    def decaps(sk, ct):
        return ml_kem._ml_kem_decaps_internal(p, sk, ct)
    return keygen, encaps, decaps


def ecdh_thu_vien():
    curve = ec.SECP256R1()
    pub = lambda sk: sk.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
    peer = lambda b: ec.EllipticCurvePublicKey.from_encoded_point(curve, b)

    def keygen():
        sk = ec.generate_private_key(curve)
        return pub(sk), sk

    def encaps(pk):
        tam = ec.generate_private_key(curve)
        return pub(tam), tam.exchange(ec.ECDH(), peer(pk))

    def decaps(sk, ct):
        return sk.exchange(ec.ECDH(), peer(ct))
    return keygen, encaps, decaps


def ml_kem_thu_vien(muc):  # thư viện chỉ có ML-KEM-768 và 1024
    KhoaRieng = getattr(mlkem, f"MLKEM{muc}PrivateKey")
    KhoaCongKhai = getattr(mlkem, f"MLKEM{muc}PublicKey")

    def keygen():
        sk = KhoaRieng.generate()
        return sk.public_key().public_bytes_raw(), sk

    def encaps(pk):
        bi_mat, ct = KhoaCongKhai.from_public_bytes(pk).encapsulate()
        return ct, bi_mat

    def decaps(sk, ct):
        return sk.decapsulate(ct)
    return keygen, encaps, decaps


# (cài đặt, tên, 3 hàm, số lần lặp). Code nhóm là Python thuần, chậm hơn nên lặp ít hơn.
LUOC_DO = [
    (NHOM, "ECDH P-256", ecdh_nhom(), 30),
    (NHOM, "ML-KEM-512", ml_kem_nhom(ML_KEM_512), 30),
    (NHOM, "ML-KEM-768", ml_kem_nhom(ml_kem.PARAMS), 30),
    (NHOM, "ML-KEM-1024", ml_kem_nhom(ML_KEM_1024), 30),
    (THU_VIEN, "ECDH P-256", ecdh_thu_vien(), 300),
    (THU_VIEN, "ML-KEM-768", ml_kem_thu_vien(768), 300),
    (THU_VIEN, "ML-KEM-1024", ml_kem_thu_vien(1024), 300),
]

# (tên, số byte, số lần lặp) - các cỡ tệp theo đề cương
TEP = [("1 KB", 1 << 10, 20), ("1 MB", 1 << 20, 10), ("10 MB", 10 << 20, 5),
       ("50 MB", 50 << 20, 3), ("100 MB", 100 << 20, 3)]


# ------------------------------------------------------------------ công cụ đo
def bam_gio(ham, *args):
    """Chạy ham(*args), trả về (kết quả, thời gian ms)."""
    t = time.perf_counter()
    kq = ham(*args)
    return kq, (time.perf_counter() - t) * 1000


def ram_dinh_kb(ham, *args):
    """Lượng RAM Python cấp phát nhiều nhất trong lúc chạy ham (KB)."""
    tracemalloc.start()
    ham(*args)
    dinh = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    return dinh / 1024


def lap_n_lan(n, ham, *args):
    """Chạy ham n lần (ham trả về các khoảng thời gian). Trả về (thời gian từng lần, CPU ms mỗi lần, kết quả cuối)."""
    cac_lan, cpu0 = [], time.process_time()
    for _ in range(n):
        thoi_gian, kq = ham(*args)
        cac_lan.append(thoi_gian)
    return cac_lan, (time.process_time() - cpu0) * 1000 / n, kq


def trung_binh(cac_lan):
    """Trung bình từng cột + trung bình và độ lệch chuẩn của tổng."""
    tong = [sum(x) for x in cac_lan]
    return [statistics.mean(cot) for cot in zip(*cac_lan)], statistics.mean(tong), statistics.stdev(tong)


# ------------------------------------------------------------------ thí nghiệm 1
def mot_lan_thiet_lap(keygen, encaps, decaps):
    (pk, sk), t_tao = bam_gio(keygen)
    (ct, bi_mat_gui), t_gui = bam_gio(encaps, pk)
    bi_mat_nhan, t_nhan = bam_gio(decaps, sk, ct)
    assert bi_mat_gui == bi_mat_nhan, "hai ben tinh ra bi mat chung khac nhau"
    return (t_tao, t_gui, t_nhan), (pk, sk, ct, bi_mat_gui)


def thi_nghiem_1():
    bang = []
    for cai_dat, ten, ham, n in LUOC_DO:
        mot_lan_thiet_lap(*ham)  # chạy nháp 1 lần trước khi đo
        cac_lan, cpu, (pk, sk, ct, bi_mat) = lap_n_lan(n, mot_lan_thiet_lap, *ham)
        (tao, gui, nhan), tong, lech = trung_binh(cac_lan)
        dong = {"Cài đặt": cai_dat, "Lược đồ": ten, "Số lần": n,
                "Tạo khóa (ms)": tao, "Bên gửi (ms)": gui, "Bên nhận (ms)": nhan,
                "Tổng (ms)": tong, "Độ lệch chuẩn (ms)": lech, "CPU (ms)": cpu}
        if cai_dat == NHOM:  # khóa của thư viện nằm trong bộ nhớ C nên không đo RAM/kích thước kiểu này
            dong |= {"RAM đỉnh (KB)": ram_dinh_kb(mot_lan_thiet_lap, *ham),
                     "Khóa công khai (B)": len(pk), "Khóa riêng (B)": len(sk),
                     "Bên gửi gửi lại (B)": len(ct), "Bí mật chung (B)": len(bi_mat),
                     "Tổng gửi qua mạng (B)": len(pk) + len(ct)}
        bang.append(dong)
        print(f"  {cai_dat:<26} {ten:<12} {tong:9.3f} ms")
    return bang


# ------------------------------------------------------------------ thí nghiệm 2
def thi_nghiem_2():
    ecdh, kem = hybrid_kex.generate_receiver_keys()  # khóa dài hạn của bên nhận
    ky = gen_ecdsa_key()                              # khóa ký của bên gửi

    def gui_va_nhan(duong_dan):
        """Một lần gửi + nhận tệp. Thời gian trả về: (thiết lập khóa, mã hóa, giải mã)."""
        gui, t1 = bam_gio(hybrid_kex.sender_establish, ecdh.public_key, kem.public_key)
        goi, t2 = bam_gio(seal_file, duong_dan, gui, ky.pri_key)
        header, t3 = bam_gio(lambda: dec_package(goi).header)  # bên nhận đọc header của gói
        nhan, t4 = bam_gio(hybrid_kex.receiver_establish, ecdh.private_key, kem.private_key, header)
        ban_ro, t5 = bam_gio(open_file, goi, nhan, ky.pub_key)
        return (t1 + t4, t2, t3 + t5), (goi, ban_ro)

    bang = []
    with tempfile.TemporaryDirectory() as thu_muc:
        duong_dan = os.path.join(thu_muc, "tep_thu.bin")
        for ten, so_byte, n in TEP:
            du_lieu = os.urandom(so_byte)
            Path(duong_dan).write_bytes(du_lieu)
            ram = ram_dinh_kb(gui_va_nhan, duong_dan) / 1024  # lần này cũng là chạy nháp
            cac_lan, cpu, (goi, ban_ro) = lap_n_lan(n, gui_va_nhan, duong_dan)
            assert ban_ro == du_lieu, "giai ma ra du lieu sai"
            (kex, ma_hoa, giai_ma), tong, lech = trung_binh(cac_lan)
            bang.append({"Tệp": ten, "Số byte": so_byte, "Số lần": n,
                         "Thiết lập khóa (ms)": kex, "Mã hóa + đóng gói (ms)": ma_hoa,
                         "Giải mã + kiểm tra (ms)": giai_ma, "Tổng (ms)": tong,
                         "Độ lệch chuẩn (ms)": lech, "CPU (ms)": cpu, "RAM đỉnh (MB)": ram,
                         "Gói tin (B)": len(goi), "Overhead (%)": (len(goi) - so_byte) / so_byte * 100})
            print(f"  {ten:>6}: {tong:9.1f} ms (thiet lap khoa {kex:.1f} ms)")
    return bang


# ------------------------------------------------------------------ ghi kết quả
MAU = ["#2a78d6", "#eb6834", "#1baf7a"]  # xanh dương, cam, xanh ngọc: người mù màu vẫn phân biệt được


def thanh_chong(ax, hang, cac_phan, nhan_cuoi, tieu_de, don_vi):
    """Biểu đồ thanh ngang chồng: mỗi hàng một mục, mỗi màu một phần, ghi nhãn ở cuối thanh."""
    trai = [0] * len(hang)
    for (ten, gia_tri), mau in zip(cac_phan.items(), MAU):
        ax.barh(hang, gia_tri, left=trai, label=ten, color=mau, height=0.6, edgecolor="white", linewidth=2)
        trai = [a + b for a, b in zip(trai, gia_tri)]
    for y, (x, chu) in enumerate(zip(trai, nhan_cuoi)):
        ax.text(x, y, "  " + chu, va="center", fontsize=9)
    ax.set_xlim(0, max(trai) * 1.3)
    ax.invert_yaxis()
    ax.set_title(tieu_de, loc="left", fontsize=10)
    ax.set_xlabel(don_vi, color="#52514e")
    ax.grid(axis="x", color="#e1e0d9")
    ax.set_axisbelow(True)
    for canh in ("top", "right", "left"):
        ax.spines[canh].set_visible(False)


def luu_hinh(fig, ax, tieu_de, ten_tep):
    fig.suptitle(tieu_de, x=0.02, ha="left", fontweight="bold")
    fig.legend(*ax.get_legend_handles_labels(), loc="lower center", ncol=3, frameon=False, fontsize=9)
    fig.tight_layout(rect=(0, 0.07, 1, 1))
    fig.savefig(OUT / ten_tep, dpi=150)
    plt.close(fig)


def ve_bieu_do(bang1, bang2):
    # Hình 1: thời gian một lần thiết lập khóa, chia 3 bước
    fig, axes = plt.subplots(2, 1, figsize=(9, 6))
    for ax, cai_dat in zip(axes, (NHOM, THU_VIEN)):
        hang = [d for d in bang1 if d["Cài đặt"] == cai_dat]
        buoc = {"Bên nhận tạo cặp khóa": "Tạo khóa (ms)", "Bên gửi: Encaps / ECDH": "Bên gửi (ms)",
                "Bên nhận: Decaps / ECDH": "Bên nhận (ms)"}
        thanh_chong(ax, [d["Lược đồ"] for d in hang], {k: [d[v] for d in hang] for k, v in buoc.items()},
                    [f"{d['Tổng (ms)']:.3g} ms" for d in hang], cai_dat, "mili giây")
    luu_hinh(fig, axes[0], "Thí nghiệm 1: thời gian một lần thiết lập khóa", "1_thoi_gian_thiet_lap_khoa.png")

    # Hình 2: số byte phải gửi qua mạng cho một lần thiết lập khóa
    hang = [d for d in bang1 if d["Cài đặt"] == NHOM]
    fig, ax = plt.subplots(figsize=(9, 3.4))
    thanh_chong(ax, [d["Lược đồ"] for d in hang],
                {"Khóa công khai bên nhận gửi đi": [d["Khóa công khai (B)"] for d in hang],
                 "Bên gửi gửi lại (khóa tạm / ciphertext)": [d["Bên gửi gửi lại (B)"] for d in hang]},
                [f"{d['Tổng gửi qua mạng (B)']} byte" for d in hang], "", "byte")
    luu_hinh(fig, ax, "Thí nghiệm 1: dữ liệu gửi qua mạng cho một lần thiết lập khóa", "2_kich_thuoc.png")

    # Hình 3: tỉ lệ thời gian khi gửi tệp, theo kích thước tệp
    fig, ax = plt.subplots(figsize=(9, 3.6))
    phan = {"Thiết lập khóa (2 bên)": "Thiết lập khóa (ms)", "Bên gửi: mã hóa + ký + đóng gói": "Mã hóa + đóng gói (ms)",
            "Bên nhận: kiểm tra + giải mã": "Giải mã + kiểm tra (ms)"}
    thanh_chong(ax, [d["Tệp"] for d in bang2],
                {k: [100 * d[v] / d["Tổng (ms)"] for d in bang2] for k, v in phan.items()},
                [f"tổng {d['Tổng (ms)']:.0f} ms" for d in bang2], "", "% tổng thời gian")
    ax.set_xticks(range(0, 101, 20))
    luu_hinh(fig, ax, "Thí nghiệm 2: thời gian gửi + nhận tệp (hybrid P-256 + ML-KEM-768)", "3_truyen_tep.png")


def ghi_csv(ten_tep, bang):
    with open(OUT / ten_tep, "w", newline="", encoding="utf-8-sig") as f:  # utf-8-sig để Excel hiện đúng tiếng Việt
        w = csv.DictWriter(f, fieldnames=bang[0].keys())
        w.writeheader()
        w.writerows({k: round(v, 4) if isinstance(v, float) else v for k, v in d.items()} for d in bang)


def moi_truong():
    try:  # Windows lưu tên CPU trong registry
        import winreg
        khoa = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
        cpu = winreg.QueryValueEx(khoa, "ProcessorNameString")[0].strip()
    except (ImportError, OSError):
        cpu = platform.processor()
    return (f"Thoi diem do : {time.strftime('%Y-%m-%d %H:%M')}\n"
            f"CPU          : {cpu} ({psutil.cpu_count(logical=False)} nhan / {psutil.cpu_count()} luong)\n"
            f"RAM          : {psutil.virtual_memory().total / 2**30:.1f} GB\n"
            f"He dieu hanh : {platform.platform()}\n"
            f"Phan mem     : Python {platform.python_version()}, cryptography {cryptography.__version__}\n")


def main():
    sys.stdout.reconfigure(errors="replace")  # console cũ không in được tiếng Việt thì thay bằng '?'
    OUT.mkdir(exist_ok=True)
    mt = moi_truong()
    print(mt)
    (OUT / "moi_truong.txt").write_text(mt, encoding="utf-8")

    print("[1] Thiet lap khoa")
    bang1 = thi_nghiem_1()
    print("\n[2] Gui + nhan tep")
    bang2 = thi_nghiem_2()

    ghi_csv("thi_nghiem_1.csv", bang1)
    ghi_csv("thi_nghiem_2.csv", bang2)
    ve_bieu_do(bang1, bang2)
    print("\nDa luu ket qua vao", OUT)


if __name__ == "__main__":
    main()
