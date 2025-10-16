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
import smtplib
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor

MSP_NAME = "LimeHawk MSP"
MSP_CONTACT = "Contact: sales@limehawk.com | 1-800-MSP-HELP"

def fetch_txt_record(domain, subdomain="", status_placeholder=None):
    if status_placeholder:
        status_placeholder.text(f"🔍 {domain}: Fetching {subdomain or 'TXT'} records...")
    try:
        full_domain = f"{subdomain}.{domain}" if subdomain else domain
        answers = dns.resolver.resolve(full_domain, 'TXT')
        if status_placeholder:
            status_placeholder.text(f"✅ {domain}: Fetched {subdomain or 'TXT'} records")
        return [str(rdata).strip('"') for rdata in answers]
    except dns.resolver.NXDOMAIN:
        if status_placeholder:
            status_placeholder.text(f"⚠️ {domain}: No {subdomain or 'TXT'} records found")
        return []
    except dns.resolver.NoAnswer:
        if status_placeholder:
            status_placeholder.text(f"⚠️ {domain}: No {subdomain or 'TXT'} records found")
        return []
    except dns.resolver.Timeout:
        if status_placeholder:
            status_placeholder.text(f"⏳ {domain}: Timeout querying {subdomain or 'TXT'} records")
        st.error(f"⏳ Timeout querying {full_domain}")
        return []
    except Exception as e:
        if status_placeholder:
            status_placeholder.text(f"❌ {domain}: Error querying {subdomain or 'TXT'} records: {e}")
        st.error(f"❌ DNS Error: {e}")
        return []

def fetch_mx_records(domain, status_placeholder=None):
    if status_placeholder:
        status_placeholder.text(f"🔍 {domain}: Fetching MX records...")
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        if status_placeholder:
            status_placeholder.text(f"✅ {domain}: Fetched MX records")
        return [(int(rdata.preference), str(rdata.exchange).rstrip('.')) for rdata in answers]
    except dns.resolver.NXDOMAIN:
        if status_placeholder:
            status_placeholder.text(f"⚠️ {domain}: No MX records found")
        return []
    except dns.resolver.NoAnswer:
        if status_placeholder:
            status_placeholder.text(f"⚠️ {domain}: No MX records found")
        return []
    except dns.resolver.Timeout:
        if status_placeholder:
            status_placeholder.text(f"⏳ {domain}: Timeout querying MX records")
        st.error(f"⏳ Timeout querying MX for {domain}")
        return []
    except Exception as e:
        if status_placeholder:
            status_placeholder.text(f"❌ {domain}: Error querying MX records: {e}")
        st.error(f"❌ MX Error: {e}")
        return []

def check_tls(mx_host, port=25):
    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(mx_host, port, timeout=10) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
        return True
    except (smtplib.SMTPNotSupportedError, ssl.SSLError, smtplib.SMTPServerDisconnected):
        return False
    except Exception:
        return None

def analyze_records(domain, status_placeholders):
    status_placeholder = status_placeholders.get(domain, st.empty())
    
    status_placeholder.text(f"🔍 {domain}: Starting analysis...")
    spf_records = fetch_txt_record(domain, "", status_placeholder)
    status_placeholder.text(f"🔍 {domain}: Analyzing SPF...")
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
    
    status_placeholder.text(f"🔍 {domain}: Analyzing DMARC...")
    dmarc_records = fetch_txt_record(domain, "_dmarc", status_placeholder)
    dmarc = {"present": False, "policy": "Missing", "reasoning": "No DMARC means no email authentication—clients could be spoofed easily.", "recommendation": "Add v=DMARC1; p=reject for robust defense"}
    for txt in dmarc_records:
        if "v=dmarc1" in txt.lower():
            dmarc["present"] = True
            pairs = re.findall(r'(\w+)=([^;]+)', txt)
            details = {k.strip(): v.strip() for k, v in pairs}
            dmarc["policy"] = details.get("p", "none")
            dmarc["reasoning"] = f"{dmarc['policy']} policy detected—{('great for blocking fakes' if dmarc['policy'] == 'reject' else 'vulnerable to spoofing, upgrade needed')}."
            dmarc["recommendation"] = "Monitor reports" if dmarc["policy"] == "reject" else "Upgrade to reject for max security."
    
    status_placeholder.text(f"🔍 {domain}: Analyzing DKIM...")
    common_selectors = ["google", "default", "selector1", "selector2"]
    dkim_count = 0
    dkim_selectors = []
    dkim_present = False
    for selector in common_selectors:
        dkim_records = fetch_txt_record(domain, f"{selector}._domainkey", status_placeholder)
        for txt in dkim_records:
            if "v=dkim1" in txt.lower():
                dkim_count += 1
                dkim_selectors.append(f"{selector}: {txt[:50]}...")
                dkim_present = True
    dkim = {"present": dkim_present, "count": dkim_count, "selectors": dkim_selectors,
            "reasoning": "DKIM present with valid records, enhancing email trust." if dkim_present else "DKIM missing—emails lack sender verification, hurting trust.",
            "recommendation": "Maintain and rotate keys annually" if dkim_present else "Add selectors for verified sending"}
    
    status_placeholder.text(f"🔍 {domain}: Fetching MX records...")
    mx_records = fetch_mx_records(domain, status_placeholder)
    mx_tls = {}
    if mx_records:
        status_placeholder.text(f"🔍 {domain}: Checking TLS support...")
        with ThreadPoolExecutor(max_workers=min(len(mx_records), 4)) as executor:
            future_to_host = {executor.submit(check_tls, host): host for _, host in mx_records}
            for future in future_to_host:
                mx_tls[future_to_host[future]] = future.result(timeout=15)
    mx = {"present": bool(mx_records), "records": mx_records, "tls": mx_tls,
          "reasoning": "No MX records—email delivery will fail." if not mx_records else 
                       "Single MX record detected—consider adding a backup for redundancy." if len(mx_records) == 1 else
                       "Multiple MX records with priorities—good redundancy, but check target security.",
          "recommendation": "Add MX records to enable email." if not mx_records else
                           "Add a secondary MX with higher priority (e.g., 20)." if len(mx_records) == 1 else
                           "Verify TLS support on all MX targets (see report)."}
    
    status_placeholder.text(f"🔍 {domain}: Analyzing BIMI...")
    bimi_records = fetch_txt_record(domain, "_bimi", status_placeholder)
    bimi = {"present": False, "record": None, "reasoning": "BIMI missing—missed chance to brand emails.", "recommendation": "Add v=bimi1 record for email branding."}
    for txt in bimi_records:
        if txt.lower().startswith("v=bimi1"):
            bimi["present"] = True
            bimi["record"] = txt
            bimi["reasoning"] = "BIMI present—emails can display your logo."
            bimi["recommendation"] = "Ensure logo is uploaded and policy complies."
    
    status_placeholder.text(f"🔍 {domain}: Analyzing MTA-STS...")
    mta_sts_records = fetch_txt_record(domain, "_mta-sts", status_placeholder)
    mta_sts = {"present": False, "record": None, "reasoning": "MTA-STS missing—email lacks TLS enforcement.", "recommendation": "Add v=sts1 record for TLS security."}
    for txt in mta_sts_records:
        if txt.lower().startswith("v=sts1"):
            mta_sts["present"] = True
            mta_sts["record"] = txt
            mta_sts["reasoning"] = "MTA-STS present—TLS enforcement active."
            mta_sts["recommendation"] = "Monitor and maintain STS policy."
    
    status_placeholder.text(f"✅ {domain}: Analysis complete")
    return dmarc, dkim, spf, mx, bimi, mta_sts

def compute_score(dmarc, dkim, spf, mx, bimi, mta_sts):
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
        if all(mx["tls"].get(host, False) for host in mx["tls"]):  # Bonus for TLS
            score += 10
    if bimi["present"]:
        score += 5
    if mta_sts["present"]:
        score += 5
    return min(score, 100)

def generate_pdf_report(domain, dmarc, dkim, spf, mx, bimi, mta_sts, score):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []
    
    elements.append(Paragraph(f"{MSP_NAME} DNS Report", styles['Title']))
    elements.append(Paragraph(f"Domain: {domain}", styles['Heading2']))
    elements.append(Paragraph(f"Overall Security Score: {score}%", styles['Heading3']))
    
    # Executive Summary
    summary = f"""
    **Executive Summary**: 
    This report assesses the DNS security of {domain}. With an overall score of {score}%, the domain excels in DMARC ({dmarc['policy']} policy), DKIM (1 record), and MX redundancy. However, SPF uses a ~all policy, leaving minor spoofing risks, and BIMI/MTA-STS are absent, missing branding and TLS enforcement opportunities. Contact {MSP_CONTACT} to enhance your security posture.
    """
    elements.append(Paragraph(summary, styles['Normal']))
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
               ["TLS Support", "\n".join([f"{h}: {'✅' if tls else '❌' if tls is not None else 'N/A'}" for h, tls in mx["tls"].items()]) if mx["present"] else "N/A"],
               ["Reasoning", mx["reasoning"]], 
               ["Action", mx["recommendation"]]]
    t = Table(mx_data)
    t.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), colors.grey), 
                          ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                          ('GRID', (0,0), (-1,-1), 1, colors.black)]))
    elements.append(t)
    elements.append(Spacer(1, 0.2 * inch))
    
    # BIMI Table
    elements.append(Paragraph("BIMI Analysis", styles['Heading3']))
    bimi_data = [["Status", "✅" if bimi["present"] else "❌"], 
                 ["Record", bimi["record"] or "None"], 
                 ["Reasoning", bimi["reasoning"]], 
                 ["Action", bimi["recommendation"]]]
    t = Table(bimi_data)
    t.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), colors.grey), 
                          ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                          ('GRID', (0,0), (-1,-1), 1, colors.black)]))
    elements.append(t)
    elements.append(Spacer(1, 0.2 * inch))
    
    # MTA-STS Table
    elements.append(Paragraph("MTA-STS Analysis", styles['Heading3']))
    mta_sts_data = [["Status", "✅" if mta_sts["present"] else "❌"], 
                    ["Record", mta_sts["record"] or "None"], 
                    ["Reasoning", mta_sts["reasoning"]], 
                    ["Action", mta_sts["recommendation"]]]
    t = Table(mta_sts_data)
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
st.markdown("**Sales Tool**: Enter domain(s) → Get PDF → Pitch security services! (No API needed)")

with st.form(key="domain_form"):
    domain_input = st.text_area("Domain(s)", placeholder="example.com\nbluepathservicedogs.org", help="Enter one domain per line")
    submit_button = st.form_submit_button("🚀 Generate Report")

if submit_button:
    domains = [d.strip() for d in domain_input.split('\n') if d.strip()]
    if not domains:
        st.error("Enter at least one domain!")
    else:
        all_results = {}
        status_placeholders = {domain: st.empty() for domain in domains}
        with st.spinner("🔍 Processing all domains..."):
            for domain in domains:
                domain = urlparse(domain).netloc if '://' in domain else domain.strip('/')
                domain = domain.lstrip('www.')
                if not domain:
                    status_placeholders[domain].text(f"❌ {domain}: Invalid domain format. Skipping.")
                    continue
                dmarc, dkim, spf, mx, bimi, mta_sts = analyze_records(domain, status_placeholders)
                score = compute_score(dmarc, dkim, spf, mx, bimi, mta_sts)
                all_results[domain] = {"dmarc": dmarc, "dkim": dkim, "spf": spf, "mx": mx, "bimi": bimi, "mta_sts": mta_sts, "score": score}
        
        # Clear status placeholders after completion
        for placeholder in status_placeholders.values():
            placeholder.empty()
        
        for domain, results in all_results.items():
            st.subheader(f"Results for {domain}")
            dmarc, dkim, spf, mx, bimi, mta_sts, score = results.values()
            
            # Overall Score
            st.metric("Overall DNS Security Score", f"{score}%")
            st.progress(score / 100)
            
            # Visual Enhancements
            col1, col2, col3, col4, col5, col6 = st.columns(6)
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
            with col5:
                bimi_status = "✅" if bimi["present"] else "❌"
                st.metric(label="BIMI", value=bimi_status, delta=bimi["recommendation"] if not bimi["present"] else None, delta_color="inverse")
                st.progress(100 if bimi["present"] else 0)
            with col6:
                mta_sts_status = "✅" if mta_sts["present"] else "❌"
                st.metric(label="MTA-STS", value=mta_sts_status, delta=mta_sts["recommendation"] if not mta_sts["present"] else None, delta_color="inverse")
                st.progress(100 if mta_sts["present"] else 0)
            
            # Detailed Tables
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
            st.table({k: [v] for k, v in mx.items() if k not in ["records", "tls"]})
            if mx["records"]:
                st.write("Records:", "\n".join([f"Priority {p}: {t}" for p, t in mx["records"]]))
                st.write("TLS Support:", "\n".join([f"{h}: {'✅' if tls else '❌' if tls is not None else 'N/A'}" for h, tls in mx["tls"].items()]))
            st.markdown(mx["recommendation"])
            st.markdown("**BIMI**")
            st.table({k: [v] for k, v in bimi.items() if k != "recommendation"})
            st.markdown(bimi["recommendation"])
            st.markdown("**MTA-STS**")
            st.table({k: [v] for k, v in mta_sts.items() if k != "recommendation"})
            st.markdown(mta_sts["recommendation"])
            
            # PDF Download
            pdf = generate_pdf_report(domain, dmarc, dkim, spf, mx, bimi, mta_sts, score)
            st.download_button("💾 Download Sales PDF", pdf.getvalue(), f"{domain}_dns_report.pdf", "application/pdf")

st.markdown("---")
st.markdown(f"**{MSP_NAME}** | {MSP_CONTACT} | Powered by Direct DNS Queries")
