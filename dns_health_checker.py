import streamlit as st
import dns.resolver
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
    try:
        full_domain = f"{subdomain}.{domain}" if subdomain else domain
        answers = dns.resolver.resolve(full_domain, 'TXT')
        return [str(rdata).strip('"') for rdata in answers]
    except dns.resolver.NXDOMAIN:
        return []
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.Timeout:
        st.error(f"⏳ Timeout querying {full_domain}")
        return []
    except Exception as e:
        st.error(f"❌ DNS Error: {e}")
        return []

def analyze_records(domain):
    spf_records = fetch_txt_record(domain)
    spf = {"present": False, "policy": "Missing", "reasoning": "SPF missing—exposes you to spoofing. A -all policy blocks unauthorized senders.", "recommendation": "Add v=spf1 -all for top-tier security"}
    for txt in spf_records:
        if txt.lower().startswith("v=spf1"):
            spf["present"] = True
            if "-all" in txt.lower():
                spf["policy"] = "-all"
                spf["reasoning"] = "Strong -all policy in place, minimizing spoofing risks."
                spf["recommendation"] = "Perfect—maintain and monitor!"
            elif "~all" in txt.lower():
                spf["policy"] = "~all"
                spf["reasoning"] = "~all soft-fails but allows some spoofing. Upgrade for full protection."
                spf["recommendation"] = "Switch to -all to lock it down."
    
    dmarc_records = fetch_txt_record(domain, "_dmarc")
    dmarc = {"present": False, "policy": "Missing", "reasoning": "No DMARC means no email authentication—clients could be spoofed easily.", "recommendation": "Add v=DMARC1; p=reject for robust defense"}
    for txt in dmarc_records:
        if "v=dmarc1" in txt.lower():
            dmarc["present"] = True
            pairs = re.findall(r'(\w+)=([^;]+)', txt)
            details = {k.strip(): v.strip() for k, v in pairs}
            dmarc["policy"] = details.get("p", "none")
            dmarc["reasoning"] = f"{dmarc['policy']} policy detected—{('great for blocking fakes' if dmarc['policy'] == 'reject' else 'vulnerable to spoofing, upgrade needed')}."
            dmarc["recommendation"] = "Monitor reports" if dmarc["policy"] == "reject" else "Upgrade to reject for max security."
    
    common_selectors = ["google", "default", "selector1", "selector2"]
    dkim_count = 0
    dkim_selectors = []
    dkim_present = False
    for selector in common_selectors:
        dkim_records = fetch_txt_record(domain, f"{selector}._domainkey")
        for txt in dkim_records:
            if "v=dkim1" in txt.lower():
                dkim_count += 1
                dkim_selectors.append(f"{selector}: {txt[:50]}...")
                dkim_present = True
    dkim = {"present": dkim_present, "count": dkim_count, "selectors": dkim_selectors,
            "reasoning": "DKIM present with valid records, enhancing email trust." if dkim_present else "DKIM missing—emails lack sender verification, hurting trust.",
            "recommendation": "Maintain and rotate keys annually" if dkim_present else "Add selectors for verified sending"}
    
    return dmarc, dkim, spf

def generate_pdf_report(domain, dmarc, dkim, spf):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []
    
    elements.append(Paragraph(f"{MSP_NAME} DNS Report", styles['Title']))
    elements.append(Paragraph(f"Domain: {domain}", styles['Heading2']))
    elements.append(Spacer(1, 0.2 * inch))
    
    # DMARC Table with Reasoning
    elements.append(Paragraph("DMARC Analysis", styles['Heading3']))
    dmarc_data = [["Status", "✅" if dmarc["present"] else "❌"], 
                  ["Policy", dmarc["policy"]], 
                  ["Reasoning", dmarc["reasoning"]], 
                  ["Action", dmarc["recommendation"]]]
    t = Table(dmarc_data)
    t.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), colors.grey), 
                          ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                          ('GRID', (0,0), (-1,-1), 1, colors.black)]))
    elements.append(t)
    elements.append(Spacer(1, 0.2 * inch))
    
    # DKIM Table with Reasoning
    elements.append(Paragraph("DKIM Analysis", styles['Heading3']))
    dkim_data = [["Status", "✅" if dkim["present"] else "❌"], 
                 ["Records", dkim["count"]], 
                 ["Reasoning", dkim["reasoning"]], 
                 ["Action", dkim["recommendation"]]]
    if dkim["selectors"]:
        dkim_data.append(["Selectors", ", ".join(dkim["selectors"])])
    t = Table(dkim_data)
    t.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), colors.grey), 
                          ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                          ('GRID', (0,0), (-1,-1), 1, colors.black)]))
    elements.append(t)
    elements.append(Spacer(1, 0.2 * inch))
    
    # SPF Table with Reasoning
    elements.append(Paragraph("SPF Analysis", styles['Heading3']))
    spf_data = [["Status", "✅" if spf["present"] else "❌"], 
                ["Policy", spf["policy"]], 
                ["Reasoning", spf["reasoning"]], 
                ["Action", spf["recommendation"]]]
    t = Table(spf_data)
    t.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), colors.grey), 
                          ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                          ('GRID', (0,0), (-1,-1), 1, colors.black)]))
    elements.append(t)
    elements.append(Spacer(1, 0.2 * inch))
    
    elements.append(Paragraph(f"{MSP_CONTACT} - Let us optimize your DNS security!", styles['Normal']))
    doc.build(elements)
    buffer.seek(0)
    return buffer

st.title(f"🔒 {MSP_NAME} DNS Checker (Direct DNS Queries)")
st.markdown("**Sales Tool**: Enter domain → Get PDF → Pitch security services! (No API needed)")

domain = st.text_input("Domain", placeholder="example.com")

if st.button("🚀 Generate Report", type="primary"):
    if not domain:
        st.error("Enter a domain!")
    else:
        with st.spinner("🔍 Querying DNS records..."):
            dmarc, dkim, spf = analyze_records(domain)
            
            # Visual Enhancements
            col1, col2, col3 = st.columns(3)
            with col1:
                dmarc_status = "✅" if dmarc["present"] else "❌"
                st.metric(label="DMARC", value=dmarc_status, delta=dmarc["recommendation"] if not dmarc["present"] else None, delta_color="inverse")
                st.progress(100 if dmarc["present"] else 0)
            with col2:
                dkim_status = "✅" if dkim["present"] else "❌"
                st.metric(label="DKIM", value=dkim_status, delta=dkim["recommendation"] if not dkim["present"] else None, delta_color="inverse")
                st.progress(100 if dkim["present"] else 0)
            with col3:
                spf_status = "✅" if spf["present"] else "❌"
                st.metric(label="SPF", value=spf_status, delta=spf["recommendation"] if not spf["present"] else None, delta_color="inverse")
                st.progress(100 if spf["present"] else 0)
            
            # Detailed Tables
            st.subheader("📊 Detailed Report")
            col1, col2 = st.columns(2)
            with col1:
                st.markdown("**DMARC**")
                st.table({k: [v] for k, v in dmarc.items() if k != "recommendation"})
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
            st.download_button("💾 Download Sales PDF", pdf.getvalue(), f"{domain}_dns_report.pdf", "application/pdf")

st.markdown("---")
st.markdown(f"**{MSP_NAME}** | {MSP_CONTACT} | Powered by Direct DNS Queries")
