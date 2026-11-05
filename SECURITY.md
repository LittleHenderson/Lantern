# Security policy

Lantern reads untrusted repositories, so parser and scanner bugs matter, and it runs two small live services
(lantern-cloud and the free-allowance gateway). If you find a way to make Lantern run code from a repository it
analyzes, read files it should not, show one person another person's results, bypass the sign-in or the limits, or
get a report to run script, please tell us privately.

**How:** the "Report a vulnerability" button on this repository's Security tab (GitHub private advisory). Not a public
issue, not a pull request. If the button is unavailable, open an issue titled "security contact" with no details and
we will reach you.

**What to expect:** a reply within 3 days saying we have read it; a fix or a written decision within 14 days for
anything that affects the live services or the report's content policy, within 30 days otherwise; credit in the
release notes if you want it. We will tell you when the fix ships. There is no bounty programme.

**In scope:** everything in this repository and the two services at lantern-cloud.fly.dev and lantern-gateway.fly.dev.
**Out of scope:** findings Lantern reports about *your own* app (that is the product working), denial of service by
volume alone (the services have daily caps and a wall clock), and anything in the public forges Lantern clones from.

Supported versions: the latest release and the latest commit on `main`. The threat model and the audit history are in
`docs/audit/`, incident notes in `docs/incidents/`.
