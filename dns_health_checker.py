import streamlit as st
import dns.resolver
import dns.exception
import re
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from io import BytesIO

MSP_NAME = "LimeHawk MSP"
MSP_CONTACT = "Contact: sales@limehawk.com | 1-800-MSP-HELP"

def fetch_txt_record(domain, subdomain=""):
    """Fetch TXT records for a domain/subdomain."""
    try:
        full_domain = f"{subdomain}.{domain}" if subdomain else domain
        answers = dns.resolver.resolve(full_domain, 'TXT')
        return [str(rdata).strip('"') for rdata in answers]  # Flatten to list of strings
    except (dns.exception.NXDOMAIN, dns.exception.NoAnswer, dns.resolver.Timeout):
        return []

def analyze_records(domain):
    # SPF: TXT on root domain
    spf_records = fetch_txt_record(domain)
    spf = {"present": False, "policy": "Missing", "recommendation": "Add v=spf1 -all"}
    for txt in spf_records:
        if txt.lower().startswith("v=spf1"):
            spf["present"] = True
            if "-all" in txt.lower():
                spf["policy"] = "-all"
                spf["recommendation"] = "Perfect!"
            elif "~all" in txt.lower():
                spf["policy"] = "~all"
                spf["recommendation"] = "Upgrade to -all"
    
    # DMARC: TXT on _dmarc subdomain
    dmarc_records = fetch_txt_record(domain, "_dmarc")
    dmarc = {"present": False, "policy": "Missing", "recommendation": "Add v=DMARC1; p=reject"}
    for txt in dmarc_records:
        if "v=dmarc1" in txt.lower():
            dmarc["present"] = True
            pairs = re.findall(r'(\w+)=([^;]+)', txt)
            details = {k.strip(): v.strip() for k, v in pairs}
            dmarc["policy"] = details.get("p", "none")
            dmarc["recommendation"] = "Monitor reports" if dmarc["policy"] == "reject" else "Upgrade to reject"
    
    # DKIM: Try common selectors
    common_selectors = ["google", "default", "selector1", "selector2"]
    dkim_count = 0
    dkim_selectors = []
    for selector in common_selectors:
        dkim_records = fetch_txt_record(domain, f"{selector}._domainkey")
        for txt in dkim_records:
            if "v=dkim1" in txt.lower():
                dkim_count += 1
                dkim_selectors.append(f"{selector}: {txt[:50]}...")
    dkim = {"present": dkim_count > 0, "count": dkim_count, "selectors": dkim_selectors, "recommendation": "Add selectors if 0 found"}
    
    return dmarc, dkim, spf

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
                 ["Records Found", dkim["count"]], 
                 ["Action", dkim["recommendation"]]]
    if dkim["selectors"]:
        for sel in dkim["selectors"]:
            dkim_data.append(["Selector", sel])
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

# UI
st.title(f"🔒 {MSP_NAME} DNS Checker (Direct DNS Queries)")
st.markdown("**Sales Tool**: Enter domain → Get PDF → Pitch security services! (No API needed)")

domain = st.text_input("Domain", placeholder="example.com")

if st.button("🚀 Generate Report", type="primary"):
    if not domain:
        st.error("Enter a domain!")
    else:
        with st.spinner("🔍 Querying DNS records..."):
            dmarc, dkim, spf = analyze_records(domain)
            
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
                st.table({k: [v] for k, v in dmarc.items() if k != "recommendation"})  # Simplified
                st.markdown(dmarc["recommendation"])
            with col2:
                st.markdown("**DKIM**")
                st.table({k: [v] for k, v in dkim.items() if k not in ["selectors", "recommendation"]})
                st.markdown(dkim["recommendation"])
                if dkim["selectors"]:
                    st.write("Selectors:", dkim["selectors"])
            st.markdown("**SPF**")
            st.table({k: [v] for k, v in spf.items() if k != "recommendation"})
            st.markdown(spf["recommendation"])
            
            # PDF Download
            pdf = generate_pdf_report(domain, dmarc, dkim, spf)
            st.download_button(
                "💾 Download Sales PDF", 
                pdf.getvalue(), 
                f"{domain}_dns_report.pdf", 
                "application/pdf"
            )

st.markdown("---")
st.markdown(f"**{MSP_NAME}** | {MSP_CONTACT} | Powered by Direct DNS Queries")
