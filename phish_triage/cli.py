import argparse

def main() -> int:
    p = argparse.ArgumentParser(prog="phish-triage")
    p.add_argument("--eml", required=True, help="Path to .eml file")
    args = p.parse_args()

    print(f"Loaded: {args.eml}")
    return 0

    urls = parsed.get("urls", [])
    print("URLs:", len(urls))
    for u in urls[:5]:
        print(" -", u)
