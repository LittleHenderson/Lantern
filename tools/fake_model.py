"""An offline, OpenAI-compatible model server for testing `lantern serve` and `lantern explain` end to end.

It answers with the hand-written explanations in examples/shop_demo_explanations.json (keyed by the
UNIT line in the prompt), so it only knows the `shop` fixture. Unknown units get a deliberately
unanchored answer, which Lantern's validator should reject.

    python tools/fake_model.py 8799
    # Settings: provider openai-compatible, model demo, base URL http://127.0.0.1:8799/v1
"""

import json
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

DEMO = json.loads((Path(__file__).parent.parent / "examples" / "shop_demo_explanations.json").read_text())


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        user = next((m["content"] for m in reversed(body.get("messages", [])) if m["role"] == "user"), "")
        m = re.search(r"^UNIT: (\S+)", user, re.M)
        if m:
            out = DEMO["units"].get(m.group(1), {"lens1": {"summary": "Does a thing with made_up_symbol."}})
        else:
            out = DEMO["metaphor"]
        data = json.dumps({"choices": [{"message": {"content": json.dumps(out)}}],
                           "usage": {"prompt_tokens": len(user) // 4, "completion_tokens": 300}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 8799), H).serve_forever()
