import streamlit as st
import dns.resolver
import re
import requests
import json
import subprocess
import os
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

def compute_score(dmarc, dkim, spf):
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
    return min(score, 100)

def is_wordpress(website):
    try:
        response = requests.get(website, timeout=10)
        html = response.text.lower()
        if 'wp-content' in html or 'generator" content="wordpress' in html or 'wp-includes' in html or 'wp-admin' in html:
            return True
    except:
        pass
    return False

def run_wpscan(website):
    api_token = os.getenv('WPSCAN_API_TOKEN')
    if not api_token:
        return {"error": "WPScan API token not set. Add WPSCAN_API_TOKEN in env vars."}
    try:
        cmd = ['wpscan', '--url', website, '--format', 'json', '--api-token', api_token, '--no-banner']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            data = json.loads(result.stdout)
            outdated_plugins = []
            vulnerabilities = []
            if 'plugins' in data:
                for plugin in data.get('plugins', {}).values():
                    if 'outdated' in plugin and plugin['outdated']:
                        outdated_plugins.append(f"{plugin['slug']} (Version: {plugin.get('version', 'Unknown')})")
                    if 'vulnerabilities' in plugin and plugin['vulnerabilities']:
                        for vuln in plugin['vulnerabilities']:
                            vulnerabilities.append(f"{plugin['slug']}: {vuln.get('title', 'Unknown')} (Severity: {vuln.get('risk_score', 'N/A')})")
            return {
                "outdated_plugins": outdated_plugins,
                "vulnerabilities": vulnerabilities
            }
        else:
            return {"error": f"WPScan failed: {result.stderr}"}
    except Exception as e:
        return {"error": str(e)}

def analyze_wordpress_vulnerabilities(domain):
    api_token = os.getenv('WPSCAN_API_TOKEN')
    if not api_token:
        return {"error": "WPScan API token not set. Add WPSCAN_API_TOKEN in env vars."}
    
    subdomains = ['', 'www', 'blog']  # Check root, www, blog
    for sub in subdomains:
        website = f"https://{sub}.{domain}" if sub else f"https://{domain}"
        if is_wordpress(website):
            return run_wpscan(website)
    return None  # No WP detected

def generate_pdf_report(domain, dmarc, dkim, spf, score, wordpress_analysis):
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
    dmarc_data = [["Status", "Present" if dmarc["present"] else "Missing"], 
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
    dkim_data = [["Status", "Present" if dkim["present"] else "Missing"], 
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
    spf_data = [["Status", "Present" if spf["present"] else "Missing"], 
                ["Policy", spf["policy"]], 
                ["Reasoning", spf["reasoning"]], 
                ["Action", spf["recommendation"]]]
    t = Table(spf_data)
    t.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), colors.grey), 
                          ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                          ('GRID', (0,0), (-1,-1), 1, colors.black)]))
    elements.append(t)
    elements.append(Spacer(1, 0.2 * inch))
    
    # WordPress Analysis
    if wordpress_analysis:
        elements.append(Paragraph("WordPress Vulnerability Analysis", styles['Heading3']))
        if "error" in wordpress_analysis:
            wp_data = [["Status", "Error"], ["Details", wordpress_analysis["error"]]]
        else:
            outdated_str = ", ".join(wp_analysis.get("outdated_plugins", [])) or "None"
            vulns_str = ", ".join(wp_analysis.get("vulnerabilities", [])) or "None"
            wp_data = [["Outdated Plugins", outdated_str], ["Vulnerabilities", vulns_str]]
        t = Table(wp_data)
        t.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), colors.grey), 
                              ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                              ('GRID', (0,0), (-1,-1), 1, colors.black)]))
        elements.append(t)
        elements.append(Spacer(1, 0.2 * inch))
    else:
        elements.append(Paragraph("WordPress Analysis", styles['Heading3']))
        wp_data = [["Status", "Not Detected"], ["Recommendation", "No WP found on root/www/blog subdomains. If WP is on a custom subdomain, provide it for a scan."]]
        t = Table(wp_data)
        t.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), colors.grey), 
                              ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                              ('GRID', (0,0), (-1,-1), 1, colors.black)]))
        elements.append(t)
        elements.append(Spacer(1, 0.2 * inch))
    
    elements.append(Paragraph(f"{MSP_CONTACT} - Let us optimize your DNS and website security!", styles['Normal']))
    doc.build(elements)
    buffer.seek(0)
    return buffer

st.title(f"🔒 {MSP_NAME} DNS Checker (Direct DNS Queries)")
st.markdown("**Sales Tool**: Enter email → Get PDF → Pitch security services! (No API needed)")

with st.form(key="email_form"):
    email = st.text_input("Email Address", placeholder="user@domain.com")
    force_wp = st.checkbox("Force WPScan (if custom subdomain or known WP)")
    submit_button = st.form_submit_button("🚀 Generate Report")

if submit_button:
    if not email or '@' not in email:
        st.error("Enter a valid email address!")
    else:
        domain = email.split('@')[1]
        website = f"https://{domain}"
        with st.spinner("🔍 Querying DNS records and scanning website..."):
            dmarc, dkim, spf = analyze_records(domain)
            score = compute_score(dmarc, dkim, spf)
            
            # WordPress Check and WPScan
            wordpress_analysis = None
            if force_wp or is_wordpress(website):
                wordpress_analysis = analyze_wordpress_vulnerabilities(domain)
            
            # Overall Score
            st.metric("Overall DNS Security Score", f"{score}%")
            st.progress(score / 100)
            
            # Visual Enhancements
            col1, col2, col3 = st.columns(3)
            with col1:
                dmarc_status = "✅" if dmarc["present"] else "❌"
                st.metric(label="DMARC", value=dmarc_status, delta=dmarc["recommendation"] if not dmarc["present"] else None, delta_color="inverse")
                st.progress(100 if dmarc["present"] else 0)
            with col2:
                dkim_status = "✅" if dkim["present"] else "❌"
                st.metric(label="DKIM", value=dkim_status, delta=dkim["recommendation"] if not dmarc["present"] else None, delta_color="inverse")
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
            
            # WordPress Analysis
            if wordpress_analysis:
                st.subheader("WordPress Vulnerability Analysis")
                if "error" in wordpress_analysis:
                    st.error(wordpress_analysis["error"])
                else:
                    outdated = wordpress_analysis.get("outdated_plugins", [])
                    vulns = wordpress_analysis.get("vulnerabilities", [])
                    st.info(f"Outdated Plugins: {', '.join(outdated) or 'None'}")
                    st.warning(f"Vulnerabilities Found: {', '.join(vulns) or 'None'}")
                    if outdated or vulns:
                        st.markdown("**Recommendation**: Schedule a full audit with LimeHawk MSP to patch these!")
            else:
                st.subheader("WordPress Analysis")
                st.info("No WordPress detected on root/www/blog subdomains. Check 'Force WPScan' for custom sites or provide the exact URL.")
            
            # PDF Download
            pdf = generate_pdf_report(domain, dmarc, dkim, spf, score, wordpress_analysis)
            st.download_button("💾 Download Sales PDF", pdf.getvalue(), f"{domain}_dns_report.pdf", "application/pdf")

st.markdown("---")
st.markdown(f"**{MSP_NAME}** | {MSP_CONTACT} | Powered by Direct DNS Queries & WPScan")
