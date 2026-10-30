"""Send one email through the configured provider, now, and say how it went.

`python -m nebula_worker.send_test <address>`: the installer runs it so a
wrong API key, sender or SMTP password shows at install time rather than at
the first person's sign-up, when it reads as Nebula never sending anything.
"""

import asyncio
import sys

from nebula_worker.adapters.base import EmailAdapter, EmailSendError
from nebula_worker.main import build_adapter
from nebula_worker.settings import get_settings

SUBJECT = "Nebula: email works"
BODY = (
    "This is the test message from your Nebula server's installer.\n\n"
    "Sign-up confirmations and password resets will arrive the same way.\n"
)


async def send_test(adapter: EmailAdapter, to: str) -> str:
    return await adapter.send(to=to, subject=SUBJECT, body=BODY)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1 or "@" not in args[0]:
        print("usage: python -m nebula_worker.send_test <address>", file=sys.stderr)
        return 2
    try:
        asyncio.run(send_test(build_adapter(get_settings()), args[0]))
    except EmailSendError as error:
        print(f"not sent: {error}", file=sys.stderr)
        return 1
    print(f"sent to {args[0]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
