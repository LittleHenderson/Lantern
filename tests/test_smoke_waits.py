"""The website check's wait for the screenshot's card (tools/waiting.js, used by tools/cloud_site_smoke.js).

The card shows one line while Lantern's server reads the picture and another when the answer is there. The check
waited for three wordings of a good answer and for nothing else, so any other answer left it waiting its whole 90
seconds and then it said only that it had timed out. Now any answer ends the wait, and one that is no reading is
said at once in the card's own words. Asked of the helper itself with Node, no browser needed."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="node is not installed")

# What the card can say when the reading has ended, and whether that is a reading. The first five are the page's own
# lines; the last three stand for what the server puts into a refusal.
ANSWERS = [("1360×880 · read by Lantern, not kept · 12 lines of text found", True),
           ("1360×880 · read by Lantern, not kept · 1 line of text found", True),
           ("1360×880 · this server cannot read text in images yet", True),
           ("?×? · text not read", True),
           ("too large: 8 MB at most", False),
           ("could not read the image", False),
           ("That file is not a picture Lantern reads (PNG, JPEG or WebP).", False),
           ("Too many screenshots are being read right now. Try again in a moment.", False)]

DRIVER = """
const w = require('./tools/waiting.js');
(async () => {
  const out = [];
  for (const lines of JSON.parse(process.argv[1])) {
    let clock = 0, reads = 0;
    const read = async () => lines[Math.min(reads++, lines.length - 1)];
    const a = await w.settled(read, 90000, async ms => { clock += ms; }, () => clock);
    out.push({ answer: a, reads, waited: clock, problem: w.shotProblem(a, 90000) });
  }
  console.log(JSON.stringify(out));
})();
"""


def ask(cards: list) -> list:
    r = subprocess.run([NODE, "-e", DRIVER, json.dumps(cards)], cwd=str(ROOT), capture_output=True, text=True,
                       encoding="utf-8", timeout=60)
    assert r.returncode == 0, r.stderr[-1500:]
    return json.loads(r.stdout)


def test_the_lines_are_the_pages_own():
    page = (ROOT / "cloud" / "lantern_cloud" / "site" / "index.html").read_text(encoding="utf-8")
    helper = (ROOT / "tools" / "waiting.js").read_text(encoding="utf-8")
    assert "info: 'reading the text…'" in page and "const WAITING = 'reading the text…';" in helper
    for words in ("'too large: 8 MB at most'", "'could not read the image'", "'text not read'", "of text found`"):
        assert words in page, words


def test_any_answer_ends_the_wait_and_one_that_is_no_reading_is_said_in_the_cards_words():
    waiting = "reading the text…"
    got = ask([[waiting, waiting, said] for said, _ in ANSWERS])
    for (said, good), res in zip(ANSWERS, got):
        assert res["reads"] == 3 and res["waited"] == 400, (said, res)          # at the answer, not at the time limit
        assert res["answer"] == {"done": True, "ok": good, "said": said}, (said, res)
        assert res["problem"] == ("" if good else f'the screenshot was not read: its card says "{said}"'), (said, res)


def test_a_card_that_never_answers_is_said_with_what_it_showed():
    still, gone = ask([["reading the text…"], [""]])
    assert still["answer"]["done"] is False and 90000 < still["waited"] <= 90400
    assert still["problem"] == 'the screenshot\'s card still said "reading the text…" after 90 seconds'
    assert gone["answer"]["done"] is False and gone["problem"] == 'the screenshot\'s card still said "nothing" after 90 seconds'


def test_the_website_check_waits_that_way():
    text = (ROOT / "tools" / "cloud_site_smoke.js").read_text(encoding="utf-8")
    assert "require('./waiting.js')" in text and "waiting.settled(" in text and "waiting.shotProblem(" in text
    # the older wait: three wordings of a good answer, and ninety seconds of silence for any other
    assert "until(p, () => /text found|cannot read|text not read/" not in text
