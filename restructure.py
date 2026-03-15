import re

with open("app.py", "r") as f:
    text = f.read()

# 1. Update Navbar to use query params
new_nav = """    <div class="nav-links">
        <a href="/?p=home" target="_self">Home</a>
        <a href="/?p=educate" target="_self">Educate</a>
        <a href="/?p=report" target="_self">Report</a>
        <a href="/?p=donate" target="_self">Donate</a>
    </div>"""
text = re.sub(r'    <div class="nav-links">\n.*?</div>', new_nav, text, flags=re.DOTALL)

# 2. Add page router variable
logic_setup = """# --- ROUTING LOGIC ---
query_params = st.query_params
active_page = query_params.get("p", "home")

# Header"""
text = text.replace("# Header", logic_setup)

# 3. Indent # Header section
text = text.replace('st.markdown("""\n<div id="home"></div>', 'if active_page == "home":\n    st.markdown("""\n<div id="home"></div>')
text = text.replace('    <p class="hero-subtitle">Phishing Hunter intercepts malicious infrastructure before it impacts your organization. Deploy automated reconnaissance, gather forensic evidence, and initiate immediate takedowns.</p>\n</div>\n""", unsafe_allow_html=True)', '    <p class="hero-subtitle">Phishing Hunter intercepts malicious infrastructure before it impacts your organization. Deploy automated reconnaissance, gather forensic evidence, and initiate immediate takedowns.</p>\n</div>\n    """, unsafe_allow_html=True)')

# 4. Indent # Dashboard section
# The dashboard starts at: if is_admin: ... wait, the layout has `with active_container:`
# We want the dashboard and `total_lapor` to be under "home" probably? Or "report"? 
# User: "home where it tell the page about, educate where it teach people about awareness, report it brings to the use of this website where people can scan domain and report, donate it brought people to do some doantion"
# Oh, so the dashboard goes into HOME or REPORT? "home where it tell the page about", Report is "where people can scan domain and report". The stats grid tells the page about (success rate, threats neutralized). We can put Dashboard in HOME.

# Wait, `if is_admin:` wraps `with active_container:` which wraps the whole DASHBOARD, REPORT results!
# If we do page separation, it's better to just structure the script with IF blocks checking `active_page`.

# Let's cleanly separate the contents of `active_container` by checking `active_page`.
# First let's find the sections in `active_container`.
