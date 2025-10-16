import streamlit as st
import requests
import json
import re
import os
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from io import BytesIO

# Dokploy ENV: Set in Dokploy dashboard
API_KEY = os.getenv("DNS_DUMPSTER_API_KEY")
if not API_KEY:
    st.error("🚨 API Key Missing! Set DNS_DUMPSTER_API_KEY in Dokploy Environment Variables.")

# MSP Branding - EDIT THESE
MSP_NAME = "Your MSP Name"
MSP_LOGO_PATH = None  # Add logo later if needed
MSP_CONTACT = "Contact: sales@yourmsp.com | 1-800-MSP-HELP"

# [PASTE THE ENTIRE PREVIOUS CODE HERE - fetch_dns_data, analyze_txt_records, generate_pdf_report FUNCTIONS]
# ... (copy from my previous response - everything between the functions)

# Streamlit UI (same as before)
st.title(f"🔒 {MSP_NAME} DNS Health Checker")
st.markdown("**Sales Tool**: Enter domain → Generate PDF → Pitch email security services!")

domain = st.text_input("Domain", placeholder="example.com", help="Just the domain name")

if st.button("🚀 Generate Report", type="primary"):
    if not domain:
        st.error("Enter a domain!")
    else:
        with st.spinner("Analyzing DNS records..."):
            data = fetch_dns_data(domain)
            if data:
                txt_records = data.get("txt", [])
                dmarc, dkim, spf = analyze_txt_records(txt_records)
                
                # Quick Preview Cards
                col1, col2, col3 = st.columns(3)
                with col1: st.metric("DMARC", "✅" if dmarc["present"] else "❌", dmarc["policy"] or "Missing")
                with col2: st.metric("DKIM", "✅" if dkim["present"] else "❌", len(dkim["selectors"]))
                with col3: st.metric("SPF", "✅" if spf["present"] else "❌", spf["policy"] or "Missing")
                
                # Detailed Tables
                st.subheader("📊 Detailed Report")
                st.markdown("### DMARC") ; st.table({k: [v] for k, v in dmarc.items() if k != "details"})
                st.markdown("### DKIM") ; st.table({k: [v] for k, v in dkim.items() if k != "selectors"})
                st.markdown("### SPF")  ; st.table({k: [v] for k, v in spf.items()})
                
                # PDF Download
                pdf_buffer = generate_pdf_report(domain, dmarc, dkim, spf)
                st.download_button(
                    "💾 Download Sales PDF",
                    pdf_buffer.getvalue(),
                    f"{domain}_dns_report.pdf",
                    "application/pdf"
                )

st.markdown("---")
st.markdown(f"**{MSP_NAME}** | {MSP_CONTACT} | Powered by dnsdumpster.com")
