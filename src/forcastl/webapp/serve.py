from __future__ import annotations

import argparse

import uvicorn

from forcastl import config


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve the FORCAST-L local web UI.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000)")
    parser.add_argument("--reload", action="store_true", help="Auto-reload on code changes (dev only).")
    args = parser.parse_args()

    config.require_data_dir()

    url = f"http://{args.host}:{args.port}"
    # ASCII only: on Windows a redirected/cp1252 stdout cannot encode "→" and
    # the launcher would crash before uvicorn starts.
    print(f"FORCAST-L web UI -> {url}")
    print("Press Ctrl+C to stop.")

    uvicorn.run(
        "forcastl.webapp.app:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
    )


if __name__ == "__main__":
    main()

