import streamlit as st
import pandas as pd
import os
import plotly.express as px
from utils.style import apply_master_theme

# --- PAGE SETUP ---
st.set_page_config(page_title="User Dashboard", page_icon="👤", layout="wide")
apply_master_theme()

# --- AUTHENTICATION SECURITY CHECK ---
if 'logged_in_user' not in st.session_state or not st.session_state.logged_in_user:
    st.error("🔒 Unauthorized Access. You must log in to view this page.")
    st.stop()

current_user = st.session_state.logged_in_user

# --- UI HEADER & LOGOUT ---
col1, col2 = st.columns([4, 1])
with col1:
    st.markdown(f"<h1>👤 Secure Vault: <span style='color:#00cfff;'>{current_user}</span></h1>", unsafe_allow_html=True)
with col2:
    st.write("<br>", unsafe_allow_html=True)
    if st.button("🚪 Secure Logout", use_container_width=True):
        st.session_state.logged_in_user = None
        st.rerun() 

st.write("---")

# --- LOAD SECURITY LOGS ---
LOGS_DB = 'data/login_logs.csv'

if os.path.exists(LOGS_DB):
    df = pd.read_csv(LOGS_DB)
    
    # FILTER: Only show failed attempts targeting THIS specific user
    failed_attempts = df[(df['Target_Username'] == current_user) & (df['Status'] == 'Failed')]

    if failed_attempts.empty:
        st.success("✅ **System Secure:** No unauthorized login attempts have been detected on your account.")
        st.balloons()
    else:
        num_attacks = len(failed_attempts)
        st.error(f"🚨 **SECURITY ALERT:** Cyber-Sentinel blocked **{num_attacks}** unauthorized attempts to access your account!")

        # --- QUICK STATS ---
        m1, m2, m3 = st.columns(3)
        m1.metric("Blocked Intrusions", num_attacks)
        m2.metric("Last Attack Attempt", failed_attempts['Timestamp'].iloc[-1])
        m3.metric("Primary Threat Origin", failed_attempts['Location'].value_counts().idxmax())

        st.write("<br>", unsafe_allow_html=True)

        # --- THE NEW INTERACTIVE THREAT MAP ---
        st.markdown("### 🗺️ Live Threat Map")
        st.write("Visualizing the exact geographical coordinates of the attackers.")
        
        # Plot the latitude and longitude on a map
        # This filters out the 0.0 coordinates from successful logins
        # Plot the latitude and longitude on an interactive 'Google Maps' style map
        map_data = failed_attempts[(failed_attempts['lat'] != 0.0) & (failed_attempts['lon'] != 0.0)]
        if not map_data.empty:
            fig_map = px.scatter_mapbox(
                map_data, 
                lat="lat", 
                lon="lon", 
                hover_name="Location",
                hover_data={"lat": False, "lon": False, "IP_Address": True, "Device": True},
                color_discrete_sequence=["#ff4b4b"], 
                zoom=4, 
                height=400
            )
            # This line forces the bright, detailed street map style!
            fig_map.update_layout(mapbox_style="open-street-map")
            fig_map.update_layout(margin={"r":0, "t":0, "l":0, "b":0}) # Removes extra borders
            
            st.plotly_chart(fig_map, use_container_width=True)
        else:
            st.info("No coordinate data available for these attacks.")
        # --- VISUAL CHARTS ---
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("#### 🌍 Origin of Cyber Attacks")
            fig_loc = px.pie(failed_attempts, names='Location', hole=0.6, 
                             color_discrete_sequence=['#ff4b4b', '#faca2b', '#a855f7', '#00cfff'])
            fig_loc.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"), height=300)
            st.plotly_chart(fig_loc, use_container_width=True)

        with c2:
            st.markdown("#### 🔑 Passwords Guessed by Attackers")
            pwd_counts = failed_attempts['Password_Tried'].value_counts().reset_index()
            fig_pwd = px.bar(pwd_counts, x='Password_Tried', y='count', color_discrete_sequence=['#ff4b4b'])
            fig_pwd.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"), height=300, xaxis_title="Guessed Password", yaxis_title="Times Tried")
            st.plotly_chart(fig_pwd, use_container_width=True)

        # --- RAW DATA TABLE ---
        st.markdown("### 📋 Detailed Intrusion Logs")
        display_df = failed_attempts[['Timestamp', 'Password_Tried', 'IP_Address', 'Location', 'Device']]
        st.dataframe(display_df, use_container_width=True, height=250)

else:
    st.success("✅ System secure. No database logs found.")