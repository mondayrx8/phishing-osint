with open("app.py", "r") as f:
    text = f.read()

text = text.replace("Phishing Hunter", "Threat Sentinel")
text = text.replace("BudakNoob.png", "BudakNoob2.png")

with open("app.py", "w") as f:
    f.write(text)
