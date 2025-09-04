import streamlit as st
import re

# Extended regex patterns to cover additional hash types with flexible matching
hash_patterns = {
    'MD5': r'^[a-fA-F0-9]{32}$',
    'SHA-1': r'^[a-fA-F0-9]{40}$',
    'SHA-256': r'^[a-fA-F0-9]{64}$',
    'SHA-512': r'^[a-fA-F0-9]{128}$',
    'SHA512': r'^[a-fA-F0-9]{128}$',
    'SHA384': r'^[a-fA-F0-9]{96}$',
    'SHA224': r'^[a-fA-F0-9]{56}$',
    'MD5-crypt':    r'^\$1\$[./0-9A-Za-z]{1,8}\$[./0-9A-Za-z]{22}$',
    'SHA-256-crypt':r'^\$5\$[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{43}$',
    'SHA-512-crypt':r'^\$6\$[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{86}$',
    'bcrypt': r'^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$',
    'yescrypt': r'^\$y\$.+',
    'scrypt': r'^\$7\$.+',
    'argon2': r'^\$argon2(id|i|d)?\$.+',
    'NTLM': r'^[a-fA-F0-9]{32}$',
    'LM': r'^[a-fA-F0-9]{32}$',
    'SHA-3-256': r'^[a-fA-F0-9]{64}$',
    'SHA-3-512': r'^[a-fA-F0-9]{128}$',
    'RIPEMD-160': r'^[a-fA-F0-9]{40}$',
    'Blake2b': r'^[a-fA-F0-9]{128}$',
    'Blake2s': r'^[a-fA-F0-9]{64}$',
    'PBKDF2': r'^\$pbkdf2-[a-z0-9]+\$.+',
    'BitLocker': r'^\$bitlocker\$[0-9]+\$[0-9]+\$[a-f0-9]+\$[0-9]+\$[0-9]+\$[a-f0-9]+\$[0-9]+\$[a-f0-9]+$',
    'FileVault2': r'^\$fvde\$.*',
    'MS Office 2010': r'^\$office\$2010.*',
    'MS Office 2013': r'^\$office\$2013.*',
    'MS Office 2007': r'^\$office\$2007.*',
    'MS Office <= 2003': r'^\$oldoffice\$.*',
    'Kerberos 5 AS-REP': r'^\$krb5asrep\$.*',
    'Kerberos 5 TGS-REP': r'^\$krb5tgs\$.*',
    'WPA-EAPOL-PBKDF2': r'^\$wpa\$[0-9]+\#.+',
    'WPA-PBKDF2-PMKID': r'^\$wpapsk\$.*',

}

def identify_hash(hash_input):
    matches = []
    for algo, pattern in hash_patterns.items():
        if re.match(pattern, hash_input):
            matches.append(algo)
    return matches

st.set_page_config(page_title="UHI-Detect", page_icon="🔐")
st.title("# UHI-Detect")
st.write("Paste any hash below to detect its possible algorithm including yescrypt, scrypt, bcrypt, argon2, and others.")

hash_input = st.text_area("Paste your hash here:", height=150)

if hash_input:
    identified_algorithms = identify_hash(hash_input.strip())
    if identified_algorithms:
        st.success("Possible algorithms detected:")
        for algo in identified_algorithms:
            st.write(f"✅ {algo}")
    else:
        st.warning("⚠️ Unable to identify the hash. It may be using an uncommon algorithm or an unsupported structure.")

st.caption("This lightweight tool is useful for forensics and quick identification in your cybersecurity workflow. For advanced detection including peppered and truncated hashes, consider using libraries like `hashID` or `Hash-Identifier` for deeper offline analysis.")
st.caption("Developed by CyGameDev")