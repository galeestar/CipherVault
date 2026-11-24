import base64
import hashlib
import math
import secrets
import string
import pandas as pd
import streamlit as st

st.set_page_config(
    page_title="CipherVault | Security & Encoding Studio",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    .block-container { padding-top: 1.4rem; padding-bottom: 2rem; }
    div[data-testid="stMetric"] {
        background-color: #131A2A;
        border: 1px solid #26324B;
        padding: 14px 18px;
        border-radius: 12px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def calculate_entropy(pwd: str) -> float:
    if not pwd:
        return 0.0
    pool = 0
    if any(c.islower() for c in pwd):
        pool += 26
    if any(c.isupper() for c in pwd):
        pool += 26
    if any(c.isdigit() for c in pwd):
        pool += 10
    if any(c in string.punctuation for c in pwd):
        pool += len(string.punctuation)
    return round(len(pwd) * math.log2(max(1, pool)), 1)


def xor_cipher_encrypt(text: str, key: str) -> str:
    if not key:
        return ""
    text_bytes = text.encode("utf-8")
    key_bytes = hashlib.sha256(key.encode("utf-8")).digest()
    xored = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(text_bytes))
    return base64.urlsafe_b64encode(xored).decode("utf-8")


def xor_cipher_decrypt(token: str, key: str) -> str:
    if not key:
        return ""
    try:
        raw = base64.urlsafe_b64decode(token.encode("utf-8"))
        key_bytes = hashlib.sha256(key.encode("utf-8")).digest()
        plain = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(raw))
        return plain.decode("utf-8")
    except Exception:
        return "Invalid ciphertext or wrong secret key."


# --- SIDEBAR: SECURITY HEALTH & QUICK GENERATOR ---
with st.sidebar:
    st.title("🔐 CipherVault")
    st.caption("Cryptographic Password, Secret Message & Hash Studio")

    st.subheader("⚡ Quick Passphrase")
    word_bank = (
        "Falcon", "Nebula", "Quantum", "Vertex", "Cobalt", "Summit",
        "Glacier", "Horizon", "Vector", "Shadow", "Cipher", "Phoenix",
        "Anchor", "Prism", "Titan", "Orbit", "Matrix", "Pulse",
    )
    if st.button("🎲 Generate 4-Word Passphrase", use_container_width=True):
        chosen = [secrets.choice(word_bank) for _ in range(4)]
        pin = str(secrets.randbelow(900) + 100)
        st.code("-".join(chosen) + "-" + pin, language=None)

    st.divider()
    st.markdown(
        """
        **🛡️ Privacy Guarantee:**
        * Everything runs **100% in memory**
        * Zero passwords or messages are logged or sent to external servers
        * Powered by Python's cryptographic `secrets` & `hashlib` modules
        """
    )

# --- MAIN HEADER ---
st.title("🔐 CipherVault: Security & Cryptography Studio")
st.caption("Generate uncrackable passwords, audit password entropy, lock secret messages & compute SHA hashes")

tab_pwd, tab_secret, tab_hash = st.tabs(
    (
        "🔑 Password Generator & Auditor",
        "✉️ Secret Message Locker",
        "🧬 Hash & Base64 Toolkit",
    )
)

# ==============================================================================
# TAB 1: CRYPTOGRAPHIC PASSWORD GENERATOR & ENTROPY AUDITOR
# ==============================================================================
with tab_pwd:
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Generate Cryptographic Passwords")
        length = st.slider("Password Length", min_value=8, max_value=64, value=20)
        use_upper = st.checkbox("Uppercase Letters (A-Z)", value=True)
        use_lower = st.checkbox("Lowercase Letters (a-z)", value=True)
        use_digits = st.checkbox("Numbers (0-9)", value=True)
        use_symbols = st.checkbox("Special Symbols (!@#$%^&*)", value=True)
        batch_count = st.selectbox("How Many to Generate", (1, 3, 5), index=1)

        charset = ""
        if use_upper:
            charset += string.ascii_uppercase
        if use_lower:
            charset += string.ascii_lowercase
        if use_digits:
            charset += string.digits
        if use_symbols:
            charset += "!@#$%^&*()-_=+[]{}?"

        if charset:
            generated_rows = []
            for _ in range(batch_count):
                pwd = "".join(secrets.choice(charset) for _ in range(length))
                ent = calculate_entropy(pwd)
                generated_rows.append({"Generated Password": pwd, "Entropy (Bits)": ent})

            st.dataframe(pd.DataFrame(generated_rows), use_container_width=True, hide_index=True)
            st.code(generated_rows[0]["Generated Password"], language=None)
        else:
            st.warning("Select at least one character type above.")

    with col2:
        st.subheader("Audit Any Password Strength")
        test_pwd = st.text_input("Type a password to test its strength", type="password")
        if test_pwd:
            bits = calculate_entropy(test_pwd)
            if bits >= 90:
                rating = "Fortress-Grade"
            elif bits >= 65:
                rating = "Strong"
            elif bits >= 45:
                rating = "Moderate"
            else:
                rating = "Weak (Easily Cracked)"

            m1, m2 = st.columns(2)
            m1.metric("Entropy Score", f"{bits} bits")
            m2.metric("Security Rating", rating)
            st.progress(min(1.0, bits / 120.0))
        else:
            st.info("Enter a password above to measure its cryptographic bit entropy.")

# ==============================================================================
# TAB 2: SECRET MESSAGE LOCKER (ENCRYPT & DECRYPT WITH A SECRET KEY)
# ==============================================================================
with tab_secret:
    st.subheader("✉️ Lock & Unlock Secret Text Messages")
    st.caption("Encrypt a message with a shared secret passphrase, then send the locked code to anyone.")

    s_col1, s_col2 = st.columns(2)
    with s_col1:
        st.markdown("**🔒 Encrypt a Message**")
        plain_msg = st.text_area("Message to Lock", height=130, placeholder="Write your confidential message here...")
        enc_key = st.text_input("Create Secret Key", type="password", key="enc_key")
        if st.button("Lock Message", type="primary", use_container_width=True):
            if plain_msg and enc_key:
                locked_token = xor_cipher_encrypt(plain_msg, enc_key)
                st.success("Message locked! Copy the encrypted code below:")
                st.code(locked_token, language=None)
            else:
                st.warning("Enter both a message and a secret key.")

    with s_col2:
        st.markdown("**🔓 Decrypt a Locked Message**")
        cipher_msg = st.text_area("Paste Locked Code", height=130, placeholder="Paste encrypted token here...")
        dec_key = st.text_input("Enter Secret Key", type="password", key="dec_key")
        if st.button("Unlock Message", use_container_width=True):
            if cipher_msg and dec_key:
                unlocked = xor_cipher_decrypt(cipher_msg.strip(), dec_key)
                st.info("Decrypted Output:")
                st.code(unlocked, language=None)
            else:
                st.warning("Paste the locked code and enter the secret key.")

# ==============================================================================
# TAB 3: CRYPTOGRAPHIC HASHING & BASE64 ENCODER
# ==============================================================================
with tab_hash:
    st.subheader("🧬 File Integrity Hasher & Text Encoder")
    raw_input = st.text_area("Enter text to hash or encode:", value="Hello World", height=100)

    if raw_input:
        encoded_bytes = raw_input.encode("utf-8")
        hash_table = pd.DataFrame(
            (
                {"Algorithm": "SHA-256", "Digest": hashlib.sha256(encoded_bytes).hexdigest()},
                {"Algorithm": "SHA-512", "Digest": hashlib.sha512(encoded_bytes).hexdigest()},
                {"Algorithm": "SHA-1", "Digest": hashlib.sha1(encoded_bytes).hexdigest()},
                {"Algorithm": "MD5", "Digest": hashlib.md5(encoded_bytes).hexdigest()},
                {"Algorithm": "Base64", "Digest": base64.b64encode(encoded_bytes).decode("utf-8")},
            )
        )
        st.dataframe(hash_table, use_container_width=True, hide_index=True)
