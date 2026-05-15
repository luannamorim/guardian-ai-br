from __future__ import annotations

import pathlib
import subprocess
import sys

_APP_PATH = pathlib.Path(__file__).parent / "app.py"


def main() -> None:
    sys.exit(
        subprocess.call(
            [
                "streamlit",
                "run",
                str(_APP_PATH),
                "--server.port=8501",
                "--server.address=0.0.0.0",
            ]
        )
    )


if __name__ == "__main__":
    main()
