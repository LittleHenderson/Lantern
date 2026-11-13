# Terms of use for lantern-cloud

Plain words, one page. These terms cover the hosted service at https://lantern-cloud.fly.dev and the free model
allowance behind it (the gateway). The Lantern software itself is MIT-licensed (`LICENSE`); run it on your own
computer and none of this applies.

## What the service is

Lantern reads a repository you point it at, or files you upload, and writes a report about its structure and its
security problems. It is a reading tool: it does not install, build or run your code, and it does not change your
repository. It is offered as a free preview for testers, with no promise that it stays up, stays free or stays the
same.

## What you may use it for

* Checking code you own or have permission to analyse. A public repository on GitHub, GitLab, Bitbucket or Codeberg
  counts as permission to read it; a private one needs you to be a collaborator (the Connect GitHub step checks that).
* Learning: the sample apps are there to be checked and broken.

## What you may not do

* Point it at code you have no right to read, or upload someone else's private code.
* Use it to find weaknesses in software you do not own and are not authorised to test.
* Run many accounts to multiply the free allowance, or use the service as free computing for anything other than
  Lantern's checks. The per-account limits (300 checks a day, one at a time) and the daily sign-up cap exist for this.
* Try to break the service, read other people's results, or send it code made to attack it. (If you find a weakness,
  tell us: `SECURITY.md` says how, and we will say thank you in the release notes.)

## Your code and your results

* Your repository is copied into a sealed working folder on the server, read, and that copy is deleted when the check
  ends. Files you upload are kept only until the check starts.
* The results (the report, the evidence page, the findings) stay in your account until you delete them, with the
  bin icon on a run or **Delete my account**. There is no other retention: nothing is kept after you delete it except
  ordinary server logs for up to 30 days, which hold request times and sizes, never code.
* If the server cannot remove a file at the moment it should (a disk fault, for example), it does not pretend: what
  you deleted can no longer be opened by anyone from that moment, the page tells you that its files are still to be
  removed, and the server tries again by itself until they are gone.
* Nothing is shared unless you press **Share** on a run; a share link is a long random address, and turning sharing off
  makes it stop working.
* We store your account id from GitHub or Google and its public name, never your email or password, and the counts
  needed for the limits.

## Explanations from a model

Only if you ask ("Explain in plain words", "Ask Lantern"), and only after you agree on screen, parts of your code are
sent to a model provider (Anthropic's Claude Haiku first, DeepSeek as the fallback) through Lantern's gateway. The
provider's own terms apply to that traffic; Lantern's gateway keeps no copy of what is sent. The free allowance has
daily and lifetime limits per account; when they are spent, the explanation stops cleanly and your report stays.

## No warranty

The service is provided as is. A finding is a signal from a deterministic check, not a guarantee that a problem exists
or that no other problem does; the report says how sure each check is and never claims an app is "secure". Lantern and
its author are not liable for decisions made on the strength of a report, or for the service being down or losing a
result. It is a preview run by one person.

## Changes

These terms can change; the date at the bottom moves when they do, and a change that reduces what you get is announced
in the release notes first. Questions: open an issue on the repository.

_Last changed: 2026-11-05._
