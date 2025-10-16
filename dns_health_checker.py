import streamlit as st
import requests
import json
import re
import os
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from io import BytesIO

# API Key from Dokploy ENV
API_KEY = os.getenv("DNS_DUMPSTER_API_KEY")
if not API_KEY:
    st.error("🚨 API Key Missing! Set DNS_DUMPSTER_API_KEY in Dokploy.")

MSP_NAME = "LimeHawk MSP"
MSP_CONTACT = "Contact: sales@limehawk.com | 1-800-MSP-HELP"

# ==================== FUNCTION 1: FETCH DNS ====================
def fetch_dns_data(domain):
    url = f"https://api.dnsdumpster.com/domain/{domain}"
    headers = {"X-API-Key": API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 429:
        st.error("⏳ Rate limit - wait 2 seconds")
    else:
        st.error(f"❌ API Error: {response.status_code}")
    return None

# ==================== FUNCTION 2: ANALYZE TXT ====================
def analyze_txt_records(txt_records):
    dmarc = {"present": False, "policy": "Missing", "recommendation": "Set p=reject"}
    dkim = {"present": False, "count": 0, "recommendation": "Configure selectors"}
    spf = {"present": False, "policy": "Missing", "recommendation": "Use -all"}
    
    for txt in txt_records:
        txt_lower = txt.lower()
        if txt_lower.startswith("v=dmarc1"):
            dmarc["present"] = True
            pairs = re.findall(r'(\w+)=([^;]+)', txt)
            details = {k.strip(): v.strip() for k, v in pairs}
            dmarc["policy"] = details.get("p", "none")
            dmarc["recommendation"] = "Monitor reports" if dmarc["policy"] == "reject" else "Upgrade to reject"
        elif txt_lower.startswith("v=dkim1"):
            dkim["present"] = True
            dkim["count"] += 1
            dkim["recommendation"] = "Rotate keys annually"
        elif txt_lower.startswith("v=spf1"):
            spf["present"] = True
            if "-all" in txt_lower:
                spf["policy"] = "-all"
                spf["recommendation"] = "Perfect!"
            else:
                spf["policy"] = "~all"
                spf["recommendation"] = "Upgrade to -all"
    
    return dmarc, dkim, spf

# ==================== FUNCTION 3: GENERATE PDF ====================
def generate_pdf_report(domain, dmarc, dkim, spf):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []
    
    elements.append(Paragraph(f"{MSP_NAME} DNS Report", styles['Title']))
    elements.append(Paragraph(f"Domain: {domain}", styles['Heading2']))
    elements.append(Spacer(1, 0.2 * inch))
    
    # DMARC Table
    elements.append(Paragraph("DMARC Analysis", styles['Heading3']))
    dmarc_data = [["Status", "✅" if dmarc["present"] else "❌"], 
                  ["Policy", dmarc["policy"]], 
                  ["Action", dmarc["recommendation"]]]
    t = Table(dmarc_data)
    t.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), colors.grey), 
                          ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke)]))
    elements.append(t)
    elements.append(Spacer(1, 0.2 * inch))
    
    # DKIM Table
    elements.append(Paragraph("DKIM Analysis", styles['Heading3']))
    dkim_data = [["Status", "✅" if dkim["present"] else "❌"], 
                 ["Records", dkim["count"]], 
                 ["Action", dkim["recommendation"]]]
    t = Table(dkim_data)
    t.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), colors.grey), 
                          ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke)]))
    elements.append(t)
    elements.append(Spacer(1, 0.2 * inch))
    
    # SPF Table
    elements.append(Paragraph("SPF Analysis", styles['Heading3']))
    spf_data = [["Status", "✅" if spf["present"] else "❌"], 
                ["Policy", spf["policy"]], 
                ["Action", spf["recommendation"]]]
    t = Table(spf_data)
    t.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), colors.grey), 
                          ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke)]))
    elements.append(t)
    elements.append(Spacer(1, 0.2 * inch))
    
    elements.append(Paragraph(MSP_CONTACT, styles['Normal']))
    doc.build(elements)
    buffer.seek(0)
    return buffer

# ==================== STREAMLIT UI ====================
st.title(f"🔒 {MSP_NAME} DNS Checker")
st.markdown("**Sales Tool**: Enter domain → Get PDF → Pitch security services!")

domain = st.text_input("Domain", placeholder="example.com", help="Just the domain name")

if st.button("🚀 Generate Report", type="primary"):
    if not domain:
        st.error("Enter a domain!")
    else:
        with st.spinner("🔍 Analyzing DNS records..."):
            data = fetch_dns_data(domain)
            if data:
                txt_records = data.get("txt", [])
                dmarc, dkim, spf = analyze_txt_records(txt_records)
                
                # Quick Status Cards
                col1, col2, col3 = st.columns(3)
                with col1: st.metric("DMARC", "✅" if dmarc["present"] else "❌", dmarc["policy"])
                with col2: st.metric("DKIM", "✅" if dkim["present"] else "❌", dkim["count"])
                with col3: st.metric("SPF", "✅" if spf["present"] else "❌", spf["policy"])
                
                # Detailed Tables
                st.subheader("📊 Detailed Report")
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown("**DMARC**")
                    st.table({k: [v] for k, v in dmarc.items()})
                with col2:
                    st.markdown("**DKIM**")
                    st.table({k: [v] for k, v in dkim.items()})
                st.markdown("**SPF**")
                st.table({k: [v] for k, v in spf.items()})
                
                # PDF Download
                pdf = generate_pdf_report(domain, dmarc, dkim, spf)
                st.download_button(
                    "💾 Download Sales PDF", 
                    pdf.getvalue(), 
                    f"{domain}_dns_report.pdf", 
                    "application/pdf"
                )

st.markdown("---")
st.markdown(f"**{MSP_NAME}** | {MSP_CONTACT} | Powered by dnsdumpster.com")
