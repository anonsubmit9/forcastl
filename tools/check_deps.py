import sys

CORE = ("requests", "tqdm", "colorama", "jinja2")
WEB = ("fastapi", "uvicorn")

missing = []
for mod in CORE + WEB:
    try:
        __import__(mod)
    except ImportError:
        missing.append(mod)

if missing:
    print(f"Missing: {', '.join(missing)}")
    print("Install: pip install -r requirements.txt -r requirements-web.txt")
    sys.exit(1)

print("All deps OK (core + web UI)")
