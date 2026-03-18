"""CLI for darkradar."""
import sys, json, argparse
from .core import Darkradar

def main():
    parser = argparse.ArgumentParser(description="DarkRadar — Dark Web Monitor. Monitor dark web for leaked credentials and brand mentions.")
    parser.add_argument("command", nargs="?", default="status", choices=["status", "run", "info"])
    parser.add_argument("--input", "-i", default="")
    args = parser.parse_args()
    instance = Darkradar()
    if args.command == "status":
        print(json.dumps(instance.get_stats(), indent=2))
    elif args.command == "run":
        print(json.dumps(instance.detect(input=args.input or "test"), indent=2, default=str))
    elif args.command == "info":
        print(f"darkradar v0.1.0 — DarkRadar — Dark Web Monitor. Monitor dark web for leaked credentials and brand mentions.")

if __name__ == "__main__":
    main()
