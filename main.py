import streamlit as st
import hashlib
import base64
import uuid
import time
import json
from email_utils import send_email
from crypto_utils import load_keys, verify_signature, sign_payload
from dotenv import load_dotenv
load_dotenv()
st.set_page_config(page_title="A2SPA Demo", layout="centered")
st.title("A2SPA Agent Email Demo")

st.markdown("""
This agent sends a secure or insecure email, showing how A2SPA stops spoofing and tampering.
""")

st.markdown("""
<div style='margin-left: 20px;'>
<p><strong>⚠️ Daily Limit:</strong> Only 100 emails can be sent per day from this demo.</p>

<p><strong>Messages you'll receive:</strong></p>
<blockquote style='margin: 10px 0; padding-left: 10px; border-left: 3px solid #ccc;'>
Normal Message: Reminder Meeting at 3pm. Join: https://zoom.us/secure-meeting
</blockquote>
<blockquote style='margin: 10px 0; padding-left: 10px; border-left: 3px solid #ccc;'>
Spoofed Message: Meeting moved to 5pm. Join: http://malicious.biz
</blockquote>

</div><br/><br/>
""", unsafe_allow_html=True)

email = st.text_input("Your email address:", placeholder="you@example.com")


if 'used_nonces' not in st.session_state:
    st.session_state.used_nonces = set()

# Button setup
col1, col2 = st.columns(2)
with col1:
    secure = st.button("Send Email with A2SPA")
with col2:
    insecure = st.button("Send Email with A2A")

col3, col4 = st.columns(2)
with col3:
    spoof_secure = st.button("Spoofed Message (A2SPA Protected)")
with col4:
    spoof_insecure = st.button("Spoofed Message (A2A Vulnerable)")

if (secure or insecure or spoof_secure or spoof_insecure) and email:
    payload = {
        "agent": "agent-messenger",
        "action": "send_email",
        "to": email,
        "message": "Reminder: Meeting at 3pm. Join: https://zoom.us/secure-meeting",
        "timestamp": int(time.time()),
        "nonce": str(uuid.uuid4())
    }

    # Simulate spoof
    if spoof_secure or spoof_insecure:
        payload["agent"] = "hacker-bot"
        payload["message"] = "Meeting moved to 5pm. Join: http://malicious.biz"

    raw = json.dumps(payload, sort_keys=True).encode()

    try:
        priv_key, pub_key = load_keys(payload["agent"])
        signature = base64.b64encode(sign_payload(priv_key, raw)).decode()
    except Exception as e:
        signature = "INVALID"
        pub_key = None

    st.subheader("Message Capsule")
    payload_out = dict(payload)
    payload_out["signature"] = signature
    st.json(payload_out)

    st.subheader("Verification Result")
    if insecure or spoof_insecure:
        st.error("A2A: Message sent with no verification.")
        success, info = send_email(payload["to"], "Meeting Update", payload["message"])
        st.info(info if success else f"Error: {info}")
    else:
        if payload["agent"] != "agent-messenger":
            st.error("Spoofed sender detected and blocked.")
        elif payload["nonce"] in st.session_state.used_nonces:
            st.error("Replay attack blocked. Nonce already used.")
        else:
            try:
                decoded_sig = base64.b64decode(signature)
                if not verify_signature(pub_key, raw, decoded_sig):
                    st.error("Invalid signature. Message blocked.")
                else:
                    st.success("Verified. Sending email...")
                    st.session_state.used_nonces.add(payload["nonce"])
                    success, info = send_email(payload["to"], "Secure Meeting Reminder", payload["message"])
                    st.info(info if success else f"Error: {info}")
            except Exception as e:
                st.error(f"Signature verification failed: {e}")

elif (secure or insecure or spoof_secure or spoof_insecure) and not email:
    st.warning("Please enter an email address.")
