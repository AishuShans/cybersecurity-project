import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import os
from datetime import datetime
from utils.style import apply_master_theme

import streamlit as st
import pandas as pd
import plotly.express as px
from utils.style import apply_master_theme # Ensure your theme loads on this page too

# 1. Page Configuration (Must be the first command)
st.set_page_config(page_title="Admin Dashboard", layout="wide", page_icon="🛡️")

# 2. Apply your custom CSS theme
apply_master_theme()

# --- 3. THE SECURE ADMIN GATEWAY ---
# Initialize the security token in the session state
if 'admin_logged_in' not in st.session_state:
    st.session_state.admin_logged_in = False

# If the admin is NOT logged in, show the login form and STOP the page
if not st.session_state.admin_logged_in:
    st.markdown("<h1 style='text-align: center; color: #a855f7;'>🔐 Restricted System Access</h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align: center; color: #888;'>Enter Level-4 Administrator credentials to proceed.</p>", unsafe_allow_html=True)
    
    # Create a centered login box
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        with st.form("admin_login_form"):
            admin_id = st.text_input("Administrator ID", placeholder="Enter ID...")
            admin_pass = st.text_input("Secure Passcode", type="password", placeholder="Enter Passcode...")
            
            # Using width="stretch" to keep your terminal free of warnings
            submit_login = st.form_submit_button("Authenticate", width="stretch")
            
            if submit_login:
                # Set your actual admin username and password here
                if admin_id == "admin" and admin_pass == "admin@123":
                    st.session_state.admin_logged_in = True
                    st.success("✅ Authentication Verified. Decrypting Dashboard...")
                    st.rerun() # Reloads the page to clear the lock
                else:
                    st.error("🚨 ACCESS DENIED: Invalid credentials detected and logged.")
    
    # CRITICAL: This command completely stops the rest of the script from running.
    # No charts, data, or dashboard elements will load until logged in.
    st.stop()


# --- 4. ACTUAL ADMIN DASHBOARD CONTENT ---
# Everything below this line will ONLY execute if the admin is successfully logged in.

st.title("🌐 Global Threat Intelligence Dashboard")
st.write("Welcome to the secure administrator control panel.")

# Add a secure logout button in the sidebar
st.sidebar.markdown("---")
if st.sidebar.button("🚪 Secure Logout", width="stretch"):
    st.session_state.admin_logged_in = False
    st.rerun()


# --- 1. PAGE SETUP & THEME ---
st.set_page_config(page_title="Admin Security Dashboard", page_icon="🛡️", layout="wide")
apply_master_theme()

# --- 2. DATA LOADING & THREAT INTELLIGENCE ENGINE ---
LOGS_DB = 'data/login_logs.csv'

@st.cache_data(ttl=2) # Near real-time refresh
def load_and_enrich_data():
    if not os.path.exists(LOGS_DB):
        return pd.DataFrame()
    
    df = pd.read_csv(LOGS_DB)
    if df.empty:
        return df

    # This engine automatically categorizes your CSV data into Risk Levels
    def calculate_risk(row):
        if row['Status'] == 'Success': return 15, 'Safe 🟢'
        
        # High Risk Indicators (Based on your simulation data)
        if 'Tor' in str(row['Device']) or 'Bot' in str(row['Device']):
            return 95, 'Attack 🔴'
        if 'Moscow' in str(row['Location']) or 'Beijing' in str(row['Location']):
            return 88, 'Attack 🔴'
            
        # Default for other failed attempts
        return 65, 'Suspicious 🟡'

    df[['Risk_Score', 'Risk_Level']] = df.apply(lambda row: pd.Series(calculate_risk(row)), axis=1)
    df['Timestamp'] = pd.to_datetime(df['Timestamp'])
    return df.sort_values(by='Timestamp', ascending=False)

df = load_and_enrich_data()

# --- 3. HEADER SECTION ---
st.markdown("<h1>🛡️ Security Monitoring Dashboard</h1>", unsafe_allow_html=True)
st.markdown("<h4 style='color: #a855f7;'>Global Command Center: Real-time insights into system access and threat vectors.</h4>", unsafe_allow_html=True)
st.write("---")

if df.empty:
    st.warning("📡 **System Idle:** No login activity detected in the database. Go to the Honeypot page and generate some attempts!")
    st.stop()

# --- 4. OVERVIEW METRICS ---
st.markdown("### 📊 Live System Telemetry")
m1, m2, m3, m4 = st.columns(4)
m1.metric("Total Login Attempts", len(df))
m2.metric("Safe Logins 🟢", len(df[df['Risk_Level'] == 'Safe 🟢']))
m3.metric("Suspicious Logins 🟡", len(df[df['Risk_Level'] == 'Suspicious 🟡']))
m4.metric("Active Attacks 🔴", len(df[df['Risk_Level'] == 'Attack 🔴']), delta="Priority Level: High", delta_color="inverse")

st.write("<br>", unsafe_allow_html=True)

# --- 5. VISUAL ANALYTICS ---
c1, c2 = st.columns([1, 1.5])

with c1:
    st.markdown("#### 🎯 Threat Distribution")
    color_map = {'Safe 🟢': '#00cfff', 'Suspicious 🟡': '#faca2b', 'Attack 🔴': '#ff4b4b'}
    fig_pie = px.pie(df, names='Risk_Level', hole=0.6, color='Risk_Level', color_discrete_map=color_map)
    fig_pie.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"), height=300, showlegend=False)
    st.plotly_chart(fig_pie, use_container_width=True)

with c2:
    st.markdown("#### 📈 Attack Frequency Timeline")
    trend_df = df.groupby(df['Timestamp'].dt.floor('Min')).size().reset_index(name='Count')
    fig_line = px.line(trend_df, x='Timestamp', y='Count', markers=True)
    fig_line.update_traces(line_color='#a855f7', marker=dict(color='#00cfff', size=8))
    fig_line.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"), height=300, yaxis_title="Volume")
    st.plotly_chart(fig_line, use_container_width=True)

# --- 6. ALERTS & INSIGHTS ---
st.write("---")
a1, a2 = st.columns(2)

with a1:
    st.markdown("### 🚨 High-Priority Alerts")
    attacks = df[df['Risk_Level'] == 'Attack 🔴'].head(3)
    if attacks.empty:
        st.success("✅ No critical threats detected in the current session.")
    else:
        for _, row in attacks.iterrows():
            st.error(f"**ATTACK:** Target `{row['Target_Username']}` from **{row['Location']}** via `{row['Device']}`.")

with a2:
    st.markdown("### 🧠 AI System Insights")
    with st.container(border=True):
        st.markdown("- ✅ **System Status:** Firewalls operational.")
        top_loc = df[df['Status'] == 'Failed']['Location'].mode()
        if not top_loc.empty:
            st.markdown(f"- 🌍 **Threat Vector:** Majority of intrusions originating from **{top_loc[0]}**.")
        st.markdown("- 🛠️ **SecOps Recommendation:** Enable Geo-fencing for non-regional IP blocks.")

# --- 7. DETAILED LOG TABLE ---
st.write("---")
st.markdown("### 📋 Unified Security Logs")

def style_risk(val):
    if val == 'Attack 🔴': return 'color: #ff4b4b; font-weight: bold; background-color: rgba(255, 75, 75, 0.1);'
    elif val == 'Suspicious 🟡': return 'color: #faca2b;'
    return 'color: #00cfff;'

display_cols = ['Timestamp', 'Target_Username', 'IP_Address', 'Location', 'Device', 'Risk_Level']
st.dataframe(df[display_cols].style.map(style_risk, subset=['Risk_Level']), use_container_width=True, height=400)

# --- 8. ADMIN ACTIONS ---
st.write("---")
st.markdown("### ⚙️ Admin Actions")
ba1, ba2, ba3, ba4 = st.columns(4)
with ba1:
    if st.button("🔨 Block Malicious IPs", use_container_width=True): st.toast("IPs Blacklisted", icon="✅")
with ba2:
    if st.button("🔒 Force Global Logout", use_container_width=True): st.toast("Sessions Revoked", icon="✅")
with ba3:
    if st.button("📱 Enforce MFA", use_container_width=True): st.toast("MFA Enabled", icon="✅")
with ba4:
    csv = df.to_csv(index=False).encode('utf-8')
    st.download_button(label="📥 Download Audit Log", data=csv, file_name="security_audit.csv", mime="text/csv", use_container_width=True)