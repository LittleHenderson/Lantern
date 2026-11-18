"""The website check waits for a page to be drawn again before its next click on that page (tools/cloud_site_smoke.js).

Done on the invite sheet draws the team page again once Lantern's server has answered. A click that begins on the
page before that and ends on the page after it is lost: the press lands on a button that is then taken away, the
release on the new one, and the browser clicks neither. Firefox's check of the website timed out that way once on
2026-11-18, waiting 30 seconds for the sheet that the click on "Add one of my reports" should have opened (the same
commit passed in the other run of the same checks). The team page drawn again is the one that says an invite link is
not used yet, so the check waits for that line before it clicks."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SMOKE = ROOT / "tools" / "cloud_site_smoke.js"
PAGE = ROOT / "cloud" / "lantern_cloud" / "site" / "index.html"


def test_done_on_the_invite_sheet_draws_the_team_page_again_with_the_open_invite():
    page = PAGE.read_text(encoding="utf-8")
    assert "el.querySelector('#invdone').onclick = () => { closeSheet(); if (S.view === 'team') render(); };" in page
    # the line only an open invite brings, and only on the team page drawn after the invite was made
    assert "owner && w.invites_open ?" in page and 'id="cancelinv"' in page


def test_the_website_check_waits_for_that_page_before_it_clicks_on_it_again():
    text = SMOKE.read_text(encoding="utf-8")
    done = text.index("await p.click('#invdone');")
    add = text.index("await p.click('#addrun');", done)
    assert "await p.waitForSelector('#cancelinv');" in text[done:add], text[done:add]
