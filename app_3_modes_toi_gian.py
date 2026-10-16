"""Giao diện CryptoShield (Streamlit).

Chạy trong thư mục P256_MLKEM768:
    python -m streamlit run Frontend/app.py
"""

import contextlib
import csv
import hashlib
import io
import secrets
import sys
import tempfile
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import streamlit as st
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

GOC = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GOC))

from ThangV2 import classical_kex, hybrid_kex, ml_kem
from Encryp_Package.package import dec_package
from Encryp_Package.pipeline import open_file, seal_file
from Encryp_Package.signature import gen_ecdsa_key
from Dang_Attack_Lab import attack_lab
from Benchmark import benchmark

st.set_page_config(page_title="CryptoShield", layout="wide")

ECDH = "Classical - ECDH P-256"
MLKEM = "Post-Quantum - ML-KEM-768"
HYBRID = "Hybrid - ECDH P-256 + ML-KEM-768"
CAC_MODE = [ECDH, MLKEM, HYBRID]


def hex_ngan(b: bytes, n=24):
    return b[:n].hex() + ("..." if len(b) > n else "")


def hkdf(shared_secret, transcript):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=transcript,
        info=b"CryptoShield",
    ).derive(shared_secret)


def alice_kex(mode, ecdh_bob, kem_bob):
    """Alice tạo khóa phiên theo mode."""
    if mode == ECDH:
        alice = classical_kex.generate_keypair()
        shared = classical_kex.derive_shared_secret(
            alice.private_key, ecdh_bob.public_key
        )
        transcript = hashlib.sha256(
            b"ECDH" + ecdh_bob.public_key + alice.public_key
        ).digest()
        return SimpleNamespace(
            session_key=hkdf(shared, transcript),
            sender_ecdh_public=alice.public_key,
            mlkem_ciphertext=b"",
            transcript_hash=transcript,
        )

    if mode == MLKEM:
        kq = ml_kem._ml_kem_encaps_internal(
            ml_kem.PARAMS, kem_bob.public_key, secrets.token_bytes(32)
        )
        transcript = hashlib.sha256(
            b"MLKEM" + kem_bob.public_key + kq.ciphertext
        ).digest()
        return SimpleNamespace(
            session_key=hkdf(kq.shared_secret, transcript),
            sender_ecdh_public=b"",
            mlkem_ciphertext=kq.ciphertext,
            transcript_hash=transcript,
        )

    return hybrid_kex.sender_establish(
        ecdh_bob.public_key, kem_bob.public_key
    )


def bob_kex(mode, ecdh_bob, kem_bob, header):
    """Bob tự tính lại khóa phiên theo mode."""
    if mode == ECDH:
        shared = classical_kex.derive_shared_secret(
            ecdh_bob.private_key, header.sender_ecdh_public
        )
        transcript = hashlib.sha256(
            b"ECDH" + ecdh_bob.public_key + header.sender_ecdh_public
        ).digest()
        if transcript != header.transcript_hash:
            raise ValueError("Transcript ECDH không khớp")
        return SimpleNamespace(
            session_key=hkdf(shared, transcript),
            sender_ecdh_public=header.sender_ecdh_public,
            mlkem_ciphertext=b"",
            transcript_hash=transcript,
        )

    if mode == MLKEM:
        shared = ml_kem._ml_kem_decaps_internal(
            ml_kem.PARAMS, kem_bob.private_key, header.mlkem_ciphertext
        )
        transcript = hashlib.sha256(
            b"MLKEM" + kem_bob.public_key + header.mlkem_ciphertext
        ).digest()
        if transcript != header.transcript_hash:
            raise ValueError("Transcript ML-KEM không khớp")
        return SimpleNamespace(
            session_key=hkdf(shared, transcript),
            sender_ecdh_public=b"",
            mlkem_ciphertext=header.mlkem_ciphertext,
            transcript_hash=transcript,
        )

    return hybrid_kex.receiver_establish(
        ecdh_bob.private_key, kem_bob.private_key, header
    )


# ------------------------------------------------------------------ 1. Tổng quan
def trang_tong_quan():
    st.title("CryptoShield: truyền tệp an toàn")
    st.graphviz_chart("""digraph {
        rankdir=LR; node [shape=box, style=rounded, fontsize=18]
        A [label="Alice"]; K [label="ECDH / ML-KEM / Hybrid"];
        H [label="HKDF -> khóa phiên"]; E [label="AES-GCM + chữ ký"];
        B [label="Bob kiểm tra và giải mã"];
        A -> K -> H -> E -> B
    }""")

    bang1 = benchmark.OUT / "thi_nghiem_1.csv"
    if bang1.exists():
        dong = {(d["Cài đặt"], d["Lược đồ"]): d
                for d in csv.DictReader(open(bang1, encoding="utf-8-sig"))}
        st.subheader("Một lần thiết lập khóa")
        for ten in ("ECDH P-256", "ML-KEM-768"):
            d = dong.get((benchmark.NHOM, ten))
            if d:
                c = st.columns(2)
                c[0].metric(f"{ten}: thời gian", f"{float(d['Tổng (ms)']):.1f} ms")
                c[1].metric(f"{ten}: dữ liệu", f"{d['Tổng gửi qua mạng (B)']} byte")


# ------------------------------------------------------------------ 2. Gửi / nhận tệp
def mo_goi(mode, khoa_bob, khoa_ky_alice, goi_tin, da_nhan):
    header = dec_package(goi_tin).header
    if header.message_id in da_nhan:
        raise ValueError(f"message_id {header.message_id} đã nhận rồi -> replay")

    ecdh, kem = khoa_bob
    phien = bob_kex(mode, ecdh, kem, header)
    ban_ro = open_file(goi_tin, phien, khoa_ky_alice)

    da_nhan.add(header.message_id)
    return header, ban_ro, phien


def trang_gui_nhan():
    st.title("Gửi / nhận tệp")
    mode = st.radio("Chọn chế độ thiết lập khóa", CAC_MODE, horizontal=True)

    ss = st.session_state
    if "khoa_bob" not in ss:
        ss.khoa_bob = hybrid_kex.generate_receiver_keys()
        ss.khoa_ky = gen_ecdsa_key()
        ss.da_nhan = set()
        ss.goi_tin, ss.so_lieu, ss.mode_goi = None, None, None

    alice, bob = st.columns(2, border=True)

    with alice:
        st.subheader("Alice gửi")
        tep = st.file_uploader("Chọn tệp cần gửi")

        if st.button("Mã hóa, ký và gửi cho Bob", type="primary", disabled=tep is None):
            with tempfile.TemporaryDirectory() as thu_muc:
                duong_dan = Path(thu_muc) / Path(tep.name).name
                duong_dan.write_bytes(tep.getvalue())
                ecdh, kem = ss.khoa_bob

                t0 = time.perf_counter()
                phien = alice_kex(mode, ecdh, kem)
                t1 = time.perf_counter()
                ss.goi_tin = seal_file(str(duong_dan), phien, ss.khoa_ky.pri_key)
                t2 = time.perf_counter()

            ss.mode_goi = mode
            ss.so_lieu = (
                tep.name, mode, (t1 - t0) * 1000,
                (t2 - t1) * 1000, len(ss.goi_tin), phien.session_key
            )

        if ss.so_lieu:
            ten, mode_da_gui, kex_ms, ma_hoa_ms, so_byte, _ = ss.so_lieu
            st.success(f"Đã gửi {ten} bằng {mode_da_gui}.")
            c = st.columns(3)
            c[0].metric("Thiết lập khóa", f"{kex_ms:.1f} ms")
            c[1].metric("Mã hóa + ký", f"{ma_hoa_ms:.1f} ms")
            c[2].metric("Kích thước package", f"{so_byte} byte")

    with bob:
        st.subheader("Bob nhận")
        if ss.goi_tin is not None:
            st.caption(f"Mode của package: {ss.mode_goi}")

        if st.button("Nhận và giải mã", type="primary", disabled=ss.goi_tin is None):
            try:
                header, ban_ro, phien_bob = mo_goi(
                    ss.mode_goi, ss.khoa_bob, ss.khoa_ky.pub_key,
                    ss.goi_tin, ss.da_nhan
                )
            except Exception as e:
                st.error(f"TỪ CHỐI: {type(e).__name__}: {e}")
            else:
                st.success(f"CHẤP NHẬN: đã nhận {header.filename} ({len(ban_ro)} byte)")
                if ss.so_lieu[-1] == phien_bob.session_key:
                    st.info("Alice và Bob tạo ra cùng khóa phiên 32 byte.")
                st.download_button(
                    f"Tải về {header.filename}", ban_ro,
                    Path(header.filename).name, on_click="ignore"
                )

        st.caption("Bấm Nhận lần nữa với cùng package để thử replay.")


# ------------------------------------------------------------------ 3. Key Inspector
def trang_key_inspector():
    st.title("Key Inspector")
    mode = st.radio("Chọn mode", CAC_MODE, horizontal=True, key="mode_inspector")

    if not st.button("Tạo một phiên trao đổi khóa mới", type="primary"):
        return

    bob_ecdh, bob_kem = hybrid_kex.generate_receiver_keys()
    alice = alice_kex(mode, bob_ecdh, bob_kem)

    header = hybrid_kex.make_package_header(
        alice, group_id="demo", message_id=str(uuid.uuid4()),
        filename="demo.txt", plaintext_size=0, plaintext_hash=bytes(32)
    )
    bob = bob_kex(mode, bob_ecdh, bob_kem, header)

    cac_khoa = []
    if mode != MLKEM:
        cac_khoa += [
            ("Bob -> Alice", "Public key ECDH của Bob", bob_ecdh.public_key),
            ("Alice -> Bob", "Public key ECDH tạm của Alice", alice.sender_ecdh_public),
        ]
    if mode != ECDH:
        cac_khoa += [
            ("Bob -> Alice", "Public key ML-KEM-768 của Bob", bob_kem.public_key),
            ("Alice -> Bob", "Ciphertext ML-KEM-768", alice.mlkem_ciphertext),
        ]

    cac_khoa += [
        ("Alice -> Bob", "Transcript hash", alice.transcript_hash),
        ("Không gửi", "Khóa phiên Alice", alice.session_key),
        ("Không gửi", "Khóa phiên Bob", bob.session_key),
    ]

    st.dataframe([
        {
            "Đi đâu": d,
            "Thành phần": ten,
            "Kích thước (byte)": len(b),
            "Giá trị": "[HIDDEN]" if "Khóa phiên" in ten else hex_ngan(b),
        }
        for d, ten, b in cac_khoa
    ], hide_index=True)

    if alice.session_key == bob.session_key:
        st.success("Alice và Bob tính ra cùng một khóa phiên 32 byte.")


# ------------------------------------------------------------------ 4. Attack Lab
DEMO = {
    "1. Luồng bình thường": attack_lab.normal_flow,
    "2. Sửa ciphertext": attack_lab.demo_tamper_ciphertext,
    "3. Sửa thông tin trao đổi khóa (header)": attack_lab.demo_tamper_header,
    "4. Phát lại gói tin (replay)": attack_lab.demo_replay_attack,
    "5. Thay khóa công khai (MITM)": attack_lab.demo_key_substitution,
}


def trang_attack_lab():
    st.title("Attack Lab")
    st.caption("Chạy các demo trong Dang_Attack_Lab/attack_lab.py của Đăng.")
    for ten, ham in DEMO.items():
        if st.button(ten):
            dau_ra = io.StringIO()
            try:
                with contextlib.redirect_stdout(dau_ra):
                    ham()
            except Exception as e:
                st.error(f"Demo lỗi: {type(e).__name__}: {e}")
            st.code(dau_ra.getvalue())


# ------------------------------------------------------------------ 5. Benchmark
def trang_benchmark():
    st.title("Benchmark: ECDH và ML-KEM")
    if st.button("Chạy lại benchmark"):
        with st.spinner("Đang đo..."):
            benchmark.main()

    if not (benchmark.OUT / "thi_nghiem_1.csv").exists():
        st.warning("Chưa có kết quả benchmark.")
        return

    moi_truong = benchmark.OUT / "moi_truong.txt"
    if moi_truong.exists():
        st.text(moi_truong.read_text(encoding="utf-8"))

    for ten_csv, anh in [
        ("thi_nghiem_1.csv", ["1_thoi_gian_thiet_lap_khoa.png", "2_kich_thuoc.png"]),
        ("thi_nghiem_2.csv", ["3_truyen_tep.png"]),
    ]:
        p = benchmark.OUT / ten_csv
        if p.exists():
            st.subheader(ten_csv)
            st.dataframe(
                list(csv.DictReader(open(p, encoding="utf-8-sig"))),
                hide_index=True,
            )
        for a in anh:
            p_anh = benchmark.OUT / a
            if p_anh.exists():
                st.image(str(p_anh))


TRANG = {
    "Tổng quan": trang_tong_quan,
    "Gửi / nhận tệp": trang_gui_nhan,
    "Key Inspector": trang_key_inspector,
    "Attack Lab": trang_attack_lab,
    "Benchmark": trang_benchmark,
}

TRANG[st.sidebar.radio("CryptoShield", list(TRANG))]()
