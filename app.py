import streamlit as st
from PIL import Image
import numpy as np
import io
import math

# --- Configuration and Constants ---
MAX_MESSAGE_CHARS = 2000
LENGTH_PREFIX_BITS = 32 # 4 bytes to store the length of the message in bits

st.set_page_config(
    page_title="Image Steganography Tool",
    layout="centered",
    initial_sidebar_state="expanded"
)

# --- Core Steganography Logic ---

def xor_cipher(text, key):
    """Simple XOR encryption/decryption function."""
    if not key:
        return text
    
    result = []
    for i, char in enumerate(text):
        key_char = key[i % len(key)]
        # Apply XOR and append the resulting character
        result.append(chr(ord(char) ^ ord(key_char)))
    return "".join(result)

def text_to_binary(text):
    """Converts a string into a binary string, prefixed with its 32-bit length."""
    # 1. Convert text to 8-bit binary string
    binary_message = ''.join(format(ord(char), '08b') for char in text)
    
    # 2. Prefix with 32-bit length
    length = len(binary_message)
    length_prefix = format(length, '032b')
    
    return length_prefix + binary_message

def binary_to_text(binary_string):
    """Converts a binary string back into a text string."""
    # Group every 8 bits and convert to character
    text = ""
    for i in range(0, len(binary_string), 8):
        byte = binary_string[i:i+8]
        if len(byte) == 8:
            text += chr(int(byte, 2))
    return text

def get_max_capacity(width, height):
    """Calculates the maximum characters that can be hidden."""
    # Each pixel (R, G, B) carries 3 bits.
    available_bits = (width * height * 3) - LENGTH_PREFIX_BITS
    # Max characters = available bits / 8 bits per character
    return math.floor(available_bits / 8)

def encode_image(img_file, secret_message, password=None):
    """Hides a secret message within an image using LSB."""
    try:
        # Load image and convert to NumPy array for efficient manipulation
        img = Image.open(img_file).convert("RGB")
        np_img = np.array(img)
        
        width, height = img.size
        
        # 1. Apply optional encryption
        if password:
            secret_message = xor_cipher(secret_message, password)

        # 2. Convert message to LSB-ready binary string (with length prefix)
        binary_data = text_to_binary(secret_message)
        data_len = len(binary_data)

        # Capacity check
        max_capacity_bits = (width * height * 3)
        if data_len > max_capacity_bits:
            st.error(f"Message is too long. Max capacity is {get_max_capacity(width, height)} characters. Message size is {len(secret_message)}.")
            return None

        # 3. LSB Encoding
        data_index = 0
        
        # Flatten the first three channels (R, G, B) of the array
        # np_img.flat returns an iterator over the array elements (R, G, B, A, R, G, B, A, ...)
        # We only modify R, G, B (index % 4 != 3)
        
        for i in range(np_img.size):
            # Skip the Alpha channel if present, though we converted to RGB above
            if i % 4 == 3:
                continue

            if data_index < data_len:
                # Get the current pixel value
                current_value = np_img.flat[i]
                # Clear the LSB (AND with 254: 11111110)
                cleared_lsb = current_value & 254
                # Set the LSB to the message bit (OR with the bit)
                new_value = cleared_lsb | int(binary_data[data_index])
                
                # Update the pixel value in the flattened array
                np_img.flat[i] = new_value
                data_index += 1
            else:
                break # All data is hidden

        # Convert NumPy array back to PIL Image
        stego_img = Image.fromarray(np_img)
        return stego_img

    except Exception as e:
        st.error(f"An error occurred during encoding: {e}")
        return None

def decode_image(img_file, password=None):
    """Retrieves a hidden message from an image."""
    try:
        img = Image.open(img_file).convert("RGB")
        np_img = np.array(img)
        
        # 1. Extract message length (first 32 bits)
        binary_length = ""
        data_index = 0
        
        # Extract the LSB from the first LENGTH_PREFIX_BITS channels
        for i in range(np_img.size):
            if i % 4 == 3: # Skip Alpha
                continue
            
            if len(binary_length) < LENGTH_PREFIX_BITS:
                # Extract the LSB: AND with 1
                lsb = np_img.flat[i] & 1
                binary_length += str(lsb)
                data_index = i + 1
            else:
                break
        
        if len(binary_length) != LENGTH_PREFIX_BITS:
            st.warning("Could not extract full length prefix. Image might be too small or corrupted.")
            return ""

        # Convert the binary length to an integer
        message_len_bits = int(binary_length, 2)

        if message_len_bits == 0 or message_len_bits > (np_img.size * 3):
            st.info("No valid hidden message found.")
            return ""

        # 2. Extract the actual message bits
        binary_message = ""
        bits_extracted = 0

        # Continue extraction from where the length extraction stopped
        for i in range(data_index, np_img.size):
            if i % 4 == 3: # Skip Alpha
                continue
            
            if bits_extracted < message_len_bits:
                lsb = np_img.flat[i] & 1
                binary_message += str(lsb)
                bits_extracted += 1
            else:
                break

        # 3. Convert binary to text
        raw_message = binary_to_text(binary_message)

        # 4. Apply optional decryption
        final_message = raw_message
        if password:
            final_message = xor_cipher(raw_message, password)

        return final_message

    except Exception as e:
        st.error(f"An error occurred during decoding: {e}")
        return "Error decoding message."


# --- Streamlit UI Components ---

st.title("🛡️ Image Steganography Tool")
st.markdown("Hide and reveal secret messages inside images using the Least Significant Bit (LSB) method.")

tab1, tab2 = st.tabs(["🔒 Hide Message (Encoder)", "🔑 Reveal Message (Decoder)"])

with tab1:
    st.header("Encode a Secret Message")
    
    # 1. Image Upload
    uploaded_file_encode = st.file_uploader(
        "Upload a Carrier Image (PNG recommended)",
        type=['png', 'jpg', 'jpeg'], 
        key='encode_uploader'
    )

    if uploaded_file_encode:
        # Display image preview and capacity info
        try:
            img = Image.open(uploaded_file_encode)
            width, height = img.size
            max_chars = get_max_capacity(width, height)
            
            st.image(img, caption="Carrier Image Preview", use_column_width=True)
            st.info(f"Image Capacity: This image can hide up to **{max_chars} characters**.")

            # 2. Secret Message Input
            secret_message = st.text_area(
                "Enter your secret message:", 
                max_chars=MAX_MESSAGE_CHARS, 
                height=150,
                key='secret_message'
            )

            # Check if message fits within hardcoded limit
            if len(secret_message) > MAX_MESSAGE_CHARS:
                st.warning(f"Message exceeds the application limit of {MAX_MESSAGE_CHARS} characters.")

            # Check if message fits within image capacity
            if len(secret_message) > max_chars:
                st.error("The message is too long for this image's capacity.")
            
            
            # 3. Optional Password System
            st.subheader("Security Options")
            use_password_encode = st.checkbox("Encrypt message with a password (Optional)", key='pass_toggle_encode')
            
            password_encode = ""
            if use_password_encode:
                password_encode = st.text_input("Enter secret password:", type="password", key='pass_input_encode')
                if not password_encode:
                    st.warning("Please enter a password for encryption.")

            # 4. Encode Button
            if st.button("Hide Message & Generate Image"):
                if not secret_message:
                    st.error("Please enter a message to hide.")
                elif use_password_encode and not password_encode:
                    st.error("Encryption is enabled, but no password was provided.")
                elif len(secret_message) > max_chars:
                    st.error("Message is too long for this image. Please shorten the message or use a larger image.")
                else:
                    with st.spinner('Encoding message...'):
                        stego_image = encode_image(uploaded_file_encode, secret_message, password_encode)

                    if stego_image:
                        st.success("Message hidden successfully! Use the button below to download the stego-image.")
                        
                        # Save image to a byte buffer for download
                        buf = io.BytesIO()
                        stego_image.save(buf, format="PNG")
                        byte_im = buf.getvalue()
                        
                        st.download_button(
                            label="Download Stego Image (PNG)",
                            data=byte_im,
                            file_name="stego_image.png",
                            mime="image/png"
                        )
                    
        except Exception as e:
            st.error(f"Error loading image: {e}")

with tab2:
    st.header("Decode a Secret Message")

    # 1. Image Upload
    uploaded_file_decode = st.file_uploader(
        "Upload a Stego Image (containing a hidden message)", 
        type=['png', 'jpg', 'jpeg'], 
        key='decode_uploader'
    )

    if uploaded_file_decode:
        # Display image preview
        st.image(Image.open(uploaded_file_decode), caption="Stego Image Preview", use_column_width=True)
        
        # 2. Optional Password System
        st.subheader("Security Options (If encryption was used)")
        use_password_decode = st.checkbox("Decrypt message with a password (Optional)", key='pass_toggle_decode')
        
        password_decode = ""
        if use_password_decode:
            password_decode = st.text_input("Enter decryption password:", type="password", key='pass_input_decode')
            if not password_decode:
                st.warning("Please enter the decryption password.")
                
        # 3. Decode Button
        if st.button("Reveal Secret Message"):
            if use_password_decode and not password_decode:
                st.error("Decryption is enabled, but no password was provided.")
            else:
                with st.spinner('Decoding message...'):
                    revealed_message = decode_image(uploaded_file_decode, password_decode)

                st.subheader("Revealed Message")
                if "Error" in revealed_message or "not found" in revealed_message:
                    st.error(revealed_message)
                else:
                    st.success("Message revealed successfully!")
                    st.text_area("Decrypted Message:", revealed_message, height=200)

---

