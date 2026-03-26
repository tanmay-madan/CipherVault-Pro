import streamlit as st
from cryptography.fernet import Fernet
import base64
import hashlib
import re
import io

# --- 1. PAGE CONFIGURATION ---
st.set_page_config(page_title="CipherVault Pro", page_icon="🛡️", layout="wide")

# --- 2. SECURITY & UTILITY FUNCTIONS ---

def get_key_from_password(password_str):
    """Derives a stable 32-byte AES key from a text password using SHA-256."""
    sha256_hash = hashlib.sha256(password_str.encode()).digest()
    return base64.urlsafe_b64encode(sha256_hash)

def calculate_hash(data):
    """Generates a SHA-256 digital fingerprint for integrity checking."""
    return hashlib.sha256(data).hexdigest()

def check_password_strength(pwd):
    """Analyzes password complexity for security best practices."""
    if len(pwd) < 8: return "🔴 Weak (Too short)", "#ff4b4b"
    if not re.search("[a-z]", pwd) or not re.search("[A-Z]", pwd):
        return "🟡 Medium (Add Uppercase)", "#ffa500"
    if not re.search("[0-9]", pwd):
        return "🟢 Strong (Add Numbers)", "#2ecc71"
    return "✅ Excellent", "#008000"

def show_preview(file_data, file_name):
    """UPDATED: Renders a visual preview compatible with Live Cloud links."""
    file_ext = file_name.split('.')[-1].lower()
    
    if file_ext in ['png', 'jpg', 'jpeg']:
        st.image(file_data, caption="🖼️ Decrypted Preview", width="stretch")
        
    elif file_ext == 'txt':
        try:
            text_content = file_data.decode('utf-8', errors='ignore')
            st.text_area("📄 Text Content", value=text_content, height=250)
        except:
            st.error("Encoding Error: Could not display text preview.")
            
    elif file_ext == 'pdf':
        # Using iframe instead of embed for better browser compatibility on the web
        base64_pdf = base64.b64encode(file_data).decode('utf-8')
        pdf_display = f'<iframe src="data:application/pdf;base64,{base64_pdf}" width="100%" height="600px" style="border:none;"></iframe>'
        st.markdown(pdf_display, unsafe_allow_html=True)
    else:
        st.info("📦 Preview not supported for this format, but the file is ready for download.")

# --- 3. THE USER INTERFACE ---
st.title("🛡️ CipherVault: Professional File Security System")
st.markdown("---")

# Sidebar for Authentication and Analysis
with st.sidebar:
    st.header("🔑 Authentication")
    password = st.text_input("Master Password", type="password", help="The key used to scramble/unscramble your files.")
    
    if password:
        msg, color = check_password_strength(password)
        st.markdown(f"**Security Level:** <span style='color:{color}'>{msg}</span>", unsafe_allow_html=True)
    
    st.divider()
    st.write("🔍 **Integrity Mode:** SHA-256 Hashing Active")
    st.write("⚙️ **Algorithm:** AES-256 (Symmetric)")
    
    if st.button("🗑️ Wipe Session"):
        st.rerun()

# Logic flow based on Password input
if password:
    key = get_key_from_password(password)
    fernet = Fernet(key)

    tab1, tab2 = st.tabs(["🔒 ENCRYPT DATA", "🔓 DECRYPT & PREVIEW"])

    # --- ENCRYPTION TAB ---
    with tab1:
        st.subheader("Secure a New File")
        file_to_lock = st.file_uploader("Upload file to Encrypt", key="enc_up")
        
        if file_to_lock:
            file_data = file_to_lock.getvalue()
            original_hash = calculate_hash(file_data)
            
            st.write(f"**File Name:** {file_to_lock.name}")
            st.write(f"**Original Hash:** `{original_hash}`")

            if st.button("🚀 Execute Encryption"):
                encrypted_data = fernet.encrypt(file_data)
                st.success("✅ Encryption Successful!")
                st.download_button(
                    label="📥 Download Encrypted File",
                    data=encrypted_data,
                    file_name=f"LOCKED_{file_to_lock.name}",
                    mime="application/octet-stream"
                )

    # --- DECRYPTION TAB ---
    with tab2:
        st.subheader("Restore and Verify Data")
        file_to_unlock = st.file_uploader("Upload 'LOCKED_' file", key="dec_up")
        
        if file_to_unlock:
            if st.button("🔍 Execute Decryption & Preview"):
                try:
                    encrypted_content = file_to_unlock.getvalue()
                    decrypted_content = fernet.decrypt(encrypted_content)
                    
                    # File identification
                    original_name = file_to_unlock.name.replace("LOCKED_", "")
                    restored_hash = calculate_hash(decrypted_content)
                    
                    st.success(f"🔓 Decryption Successful! Integrity Verified.")
                    st.write(f"**Restored Hash:** `{restored_hash}`")
                    
                    st.divider()
                    show_preview(decrypted_content, original_name)
                    st.divider()

                    st.download_button(
                        label="📥 Download Restored File",
                        data=decrypted_content,
                        file_name=original_name,
                        mime="application/octet-stream"
                    )
                except Exception:
                    st.error("❌ Decryption Failed! Wrong password or the file was tampered with.")
else:
    st.warning("👈 Enter a password in the sidebar to unlock the vault.")

# --- 4. THE FOOTER ---
st.markdown("---")
st.markdown("<center>Winter School Cyber Project 2026 | Built by <b>Tanmay Madan</b></center>", unsafe_allow_html=True)
