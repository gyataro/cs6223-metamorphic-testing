import falco

c = falco.Client(endpoint="unix:///run/falco/falco.sock", output_format="json")

for event in c.sub():
    print(event)