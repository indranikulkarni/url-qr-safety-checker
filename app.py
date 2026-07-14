"""
URL / QR Code Safety Checker
Paste a URL or upload a QR code image -> get a risk verdict using:
  1. Rule-based heuristics (typosquatting, shorteners, suspicious TLDs, etc.)
  2. Optional Google Safe Browsing API lookup (needs free API key)

Run with:  streamlit run app.py
"""

import streamlit as st
from heuristics import run_all_heuristics
from safe_browsing import check_safe_browsing
from qr_reader import read_qr_code

st.set_page_config(page_title="URL/QR Safety Checker", page_icon="🔍", layout="centered")

st.title("🔍 URL & QR Code Safety Checker")
st.caption("Paste a link or upload a QR code to check it for phishing / malicious indicators.")

# --- Sidebar: optional API key -------------------------------------------
with st.sidebar:
    st.header("Settings")
    api_key = st.text_input("Google Safe Browsing API key (optional)", type="password")
    st.markdown(
        "Don't have one? The heuristic checks still work without it. "
        "[Get a free key](https://developers.google.com/safe-browsing/v4/get-started)"
    )

# --- Input: URL text or QR image ------------------------------------------
tab1, tab2 = st.tabs(["Paste URL", "Upload QR Code"])

url_input = None

with tab1:
    typed_url = st.text_input("Enter a URL", placeholder="https://example.com")
    if typed_url:
        url_input = typed_url.strip()

with tab2:
    qr_file = st.file_uploader("Upload a QR code image", type=["png", "jpg", "jpeg"])
    if qr_file:
        decoded = read_qr_code(qr_file)
        if decoded:
            st.success(f"Decoded content: {decoded}")
            url_input = decoded.strip()
        else:
            st.error("Could not detect a QR code in that image.")

# --- Run checks -------------------------------------------------------------
if url_input:
    st.divider()
    st.subheader("Result")

    if not (url_input.startswith("http://") or url_input.startswith("https://")):
        url_input = "http://" + url_input  # normalize so parsing works

    result = run_all_heuristics(url_input)

    verdict_colors = {
        "LIKELY SAFE": "green",
        "SUSPICIOUS": "orange",
        "LIKELY MALICIOUS": "red",
    }
    color = verdict_colors[result["verdict"]]
    st.markdown(f"### Verdict: :{color}[{result['verdict']}]")
    st.write(f"**URL analyzed:** `{result['url']}`")
    st.write(f"**Risk score:** {result['score']}")

    if result["flags"]:
        st.write("**Heuristic flags raised:**")
        for f in result["flags"]:
            st.write(f"- {f}")
    else:
        st.write("No heuristic red flags found.")

    # Optional Safe Browsing check
    if api_key:
        with st.spinner("Checking Google Safe Browsing..."):
            sb_result = check_safe_browsing(url_input, api_key)
        if sb_result["checked"]:
            if sb_result["malicious"]:
                st.error(f"⚠️ Google Safe Browsing flagged this URL: {', '.join(sb_result['threats'])}")
            else:
                st.success("✅ Google Safe Browsing found no known threats.")
        else:
            st.warning(f"Safe Browsing check skipped: {sb_result['error']}")
    else:
        st.info("Tip: add a Google Safe Browsing API key in the sidebar for a live threat-database check.")

else:
    st.info("Paste a URL or upload a QR code image above to get started.")
