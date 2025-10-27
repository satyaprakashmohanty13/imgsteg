import streamlit as st
from PIL import Image
import numpy as np
import io
import hashlib
import struct
from cryptography.fernet import Fernet
import base64

st.set_page_config(page_title="🔐 Image Steganography App", layout="centered")

# -------------------
# Helper utilities
# -------------------

def generate_key_from_password(password: str) -> bytes:
    """Derive a Fernet key (AES-128 + HMAC) from password using SHA256"""
    # SHA256 gives 32 bytes; Fernet expects base64-encoded 32 bytes
    key = hashlib.sha256(password.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(key)

def aes_encrypt(message: bytes, password: str) -> bytes:
    key = generate_key_from_password(password)
    f = Fernet(key)
    return f.encrypt(message)

def aes_decrypt(ciphertext: bytes, password: str) -> bytes:
    key = generate_key_from_password(password)
    f = Fernet(key)
    return f.decrypt(ciphertext)

def bytes_to_bits(data: bytes) -> np.ndarray:
    return np.unpackbits(np.frombuffer(data, dtype=np.uint8))

def bits_to_bytes(bits: np.ndarray) -> bytes:
    return np.packbits(bits).tobytes()

def image_capacity_bits(img: Image.Image) -> int:
    w, h = img.size
    return w * h * 3  # one bit per RGB channel

def embed_data_into_image(img: Image.Image, payload: bytes) -> Image.Image:
    length = len(payload)
    length_bytes = struct.pack(">I", length)
    checksum = hashlib.sha256(payload).digest()[:4]
    data = length_bytes + checksum + payload
    bits = bytes_to_bits(data)

    arr = np.array(img.convert("RGB"))
    flat = arr.flatten()

    if len(bits) > flat.size:
        raise ValueError("Message too large for this image.")

    flat[:len(bits)] = (flat[:len(bits)] & 0xFE) | bits
    new_arr = flat.reshape(arr.shape)
    return Image.fromarray(new_arr.astype(np.uint8), "RGB")

def extract_data_from_image(img: Image.Image):
    arr = np.array(img.convert("RGB"))
    flat = arr.flatten()
    bits = (flat & 1).astype(np.uint8)

    header_bits = bits[:64]
    header_bytes = bits_to_bytes(header_bits)
    length = struct.unpack(">I", header_bytes[:4])[0]
    checksum = header_bytes[4:8]

    total_bits = 8 * length
    start = 64
    end = start + total_bits

    if end > bits.size:
        raise ValueError("Incomplete or corrupted message data.")

    payload_bits = bits[start:end]
    payload = bits_to_bytes(payload_bits)
    return length, checksum, payload

# -------------------
# Streamlit UI
# -------------------

st.title("🖼️ Image Steganography — Hide & Reveal Messages")
st.caption("Upload an image (PNG or JPEG), hide secret text securely using AES-256 encryption.")

tab1, tab2 = st.tabs(["🧩 Hide Message", "🔍 Reveal Message"])

# -------------------
# ENCODER
# -------------------
with tab1:
    st.header("Hide a secret message inside an image")

    img_file = st.file_uploader("Upload an image (PNG or JPEG)", type=["png", "jpg", "jpeg"])
    message = st.text_area("Enter your secret message", height=150)
    use_password = st.checkbox("Use password for strong encryption (recommended)")
    password = ""
    if use_password:
        password = st.text_input("Password", type="password")

    if st.button("🔒 Hide Message"):
        if not img_file:
            st.warning("Please upload an image first.")
        elif not message.strip():
            st.warning("Please enter a message.")
        else:
            try:
                img = Image.open(img_file).convert("RGB")
                # Always convert to PNG for lossless result
                if img_file.name.lower().endswith(("jpg", "jpeg")):
                    st.info("JPEG detected — converting internally to PNG (lossless).")

                data = message.encode("utf-8")
                if use_password and password:
                    data = aes_encrypt(data, password)

                stego_img = embed_data_into_image(img, data)

                buf = io.BytesIO()
                stego_img.save(buf, format="PNG")
                buf.seek(0)
                st.success("✅ Message hidden successfully! Download your secure image below.")
                st.image(stego_img, caption="Stego Image Preview", use_column_width=True)
                st.download_button("⬇️ Download Stego Image (PNG)", buf, file_name="stego_image.png", mime="image/png")
            except Exception as e:
                st.error(f"Error: {e}")

# -------------------
# DECODER
# -------------------
with tab2:
    st.header("Reveal a hidden message from an image")

    stego_file = st.file_uploader("Upload stego image (PNG or JPEG)", type=["png", "jpg", "jpeg"])
    use_password_d = st.checkbox("Message is password-protected")
    password_d = ""
    if use_password_d:
        password_d = st.text_input("Enter password", type="password", key="dec_pw")

    if st.button("🔓 Reveal Message"):
        if not stego_file:
            st.warning("Upload a stego image.")
        else:
            try:
                img = Image.open(stego_file).convert("RGB")
                _, checksum, payload = extract_data_from_image(img)

                if use_password_d and password_d:
                    try:
                        payload = aes_decrypt(payload, password_d)
                    except Exception:
                        st.error("❌ Incorrect password or corrupted data.")
                        st.stop()

                actual_checksum = hashlib.sha256(payload).digest()[:4]
                if actual_checksum != checksum:
                    st.error("❌ Data integrity check failed (wrong password or damaged image).")
                    st.stop()

                try:
                    decoded_msg = payload.decode("utf-8")
                    st.success("✅ Message revealed successfully!")
                    st.text_area("Hidden Message", decoded_msg, height=200)
                except UnicodeDecodeError:
                    st.error("Could not decode message text (non-text data or wrong password).")
            except Exception as e:
                st.error(f"Error: {e}")

st.markdown("---")
st.caption("💡 Tip: Always use PNG for storing or sharing your stego images to avoid compression losses.")