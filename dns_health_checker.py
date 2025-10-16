import streamlit as st
import dns.resolver
import re
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from io import BytesIO
from urllib.parse import urlparse

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

def fetch_mx_records(domain):
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        return [(int(rdata.preference), str(rdata.exchange).rstrip('.')) for rdata in answers]
    except dns.resolver.NXDOMAIN:
        return []
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.Timeout:
        st.error(f"⏳ Timeout querying MX for {domain}")
        return []
    except Exception as e:
        st.error(f"❌ MX Error: {e}")
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
    
    mx_records = fetch_mx_records(domain)
    mx = {"present": bool(mx_records), "records": mx_records,
          "reasoning": "No MX records—email delivery will fail." if not mx_records else 
                       "Single MX record detected—consider adding a backup for redundancy." if len(mx_records) == 1 else
                       "Multiple MX records with priorities—good redundancy, but check target security.",
          "recommendation": "Add MX records to enable email." if not mx_records else
                           "Add a secondary MX with higher priority (e.g., 20)." if len(mx_records) == 1 else
                           "Verify MX targets support TLS (e.g., test with our tools)."}
    
    return dmarc, dkim, spf, mx

def compute_score(dmarc, dkim, spf, mx):
    score = 0
    if dmarc["present"]:
        if dmarc["policy"] == "reject":
            score += 40
        elif dmarc["policy"] == "quarantine":
            score += 30
        else:
            score += 20
    if dkim["present"]:
        score += 30
    if spf["present"]:
        if spf["policy"] == "-all":
            score += 30
        else:
            score += 20
    if mx["present"]:
        score += 10  # Basic presence
        if len(mx["records"]) > 1:  # Bonus for redundancy
            score += 10
    return min(score, 100)

def generate_pdf_report(domain, dmarc, dkim, spf, mx, score):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []
    
    elements.append(Paragraph(f"{MSP_NAME} DNS Report", styles['Title']))
    elements.append(Paragraph(f"Domain: {domain}", styles['Heading2']))
    elements.append(Paragraph(f"Overall Security Score: {score}%", styles['Heading3']))
    elements.append(Spacer(1, 0.2 * inch))
    
    # DMARC Table
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
    
    # DKIM Table
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
    
    # SPF Table
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
    
    # MX Table
    elements.append(Paragraph("MX Analysis", styles['Heading3']))
    mx_data = [["Status", "✅" if mx["present"] else "❌"], 
               ["Records", "\n".join([f"Priority {p}: {t}" for p, t in mx["records"]]) if mx["present"] else "None"], 
               ["Reasoning", mx["reasoning"]], 
               ["Action", mx["recommendation"]]]
    t = Table(mx_data)
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

with st.form(key="domain_form"):
    domain_input = st.text_input("Domain", placeholder="example.com")
    submit_button = st.form_submit_button("🚀 Generate Report")

if submit_button:
    if not domain_input:
        st.error("Enter a domain!")
    else:
        # Sanitize domain input
        domain = urlparse(domain_input).netloc if '://' in domain_input else domain_input.strip('/')
        domain = domain.lstrip('www.')  # Optional: strip www. for cleaner DNS lookups
        
        with st.spinner("🔍 Querying DNS records..."):
            dmarc, dkim, spf, mx = analyze_records(domain)
            score = compute_score(dmarc, dkim, spf, mx)
            
            # Overall Score
            st.metric("Overall DNS Security Score", f"{score}%")
            st.progress(score / 100)
            
            # Visual Enhancements
            col1, col2, col3, col4 = st.columns(4)
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
            with col4:
                mx_status = "✅" if mx["present"] else "❌"
                st.metric(label="MX", value=mx_status, delta=mx["recommendation"] if not mx["present"] else None, delta_color="inverse")
                st.progress(100 if mx["present"] else 0)
            
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
            st.markdown("**MX**")
            st.table({k: [v] for k, v in mx.items() if k not in ["records"]})
            if mx["records"]:
                st.write("Records:", "\n".join([f"Priority {p}: {t}" for p, t in mx["records"]]))
            st.markdown(mx["recommendation"])
            
            # PDF Download
            pdf = generate_pdf_report(domain, dmarc, dkim, spf, mx, score)
            st.download_button("💾 Download Sales PDF", pdf.getvalue(), f"{domain}_dns_report.pdf", "application/pdf")

st.markdown("---")
st.markdown(f"**{MSP_NAME}** | {MSP_CONTACT} | Powered by Direct DNS Queries")
