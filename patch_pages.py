import re

with open("app.py", "r") as f:
    text = f.read()

# 1. Update the custom navbar links
new_nav = """    <div class="nav-links">
        <a href="/?p=home" target="_self">Home</a>
        <a href="/?p=educate" target="_self">Educate</a>
        <a href="/?p=report" target="_self">Report</a>
        <a href="/?p=donate" target="_self">Donate</a>
    </div>"""

text = re.sub(r'    <div class="nav-links">\n.*?</div>', new_nav, text, flags=re.DOTALL)


# Now wrap each section in a conditional block based on query param 'p'
# First getting the page param:
page_logic_setup = """# --- ROUTING LOGIC ---
p = st.query_params.get("p", "home")

# Header / Home
"""
text = text.replace("# Header\n", page_logic_setup)

# Change the "# Header / Home" rendering conditionally
text = text.replace('st.markdown("""\n<div id="home"></div>', 'if p == "home":\n    st.markdown("""\n<div id="home"></div>')
# Indent the whole hero block
hero_block_old = """    <h1 class="hero-title">Expose <span class="text-gradient">Unknown Threats</span> in Seconds</h1>
    <p class="hero-subtitle">Phishing Hunter intercepts malicious infrastructure before it impacts your organization. Deploy automated reconnaissance, gather forensic evidence, and initiate immediate takedowns.</p>
</div>
\"\"\", unsafe_allow_html=True)"""

hero_block_new = """    <h1 class="hero-title">Expose <span class="text-gradient">Unknown Threats</span> in Seconds</h1>
    <p class="hero-subtitle">Phishing Hunter intercepts malicious infrastructure before it impacts your organization. Deploy automated reconnaissance, gather forensic evidence, and initiate immediate takedowns.</p>
</div>
\"\"\", unsafe_allow_html=True)"""
text = text.replace(hero_block_old, hero_block_new)

with open("app.py", "w") as f:
    f.write(text)

