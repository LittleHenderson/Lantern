# Behaviour benchmark: Corkboard, safe and with each planted problem

`python bench/behaviour/run_behaviour.py WORKDIR`, 2026-11-19 (UTC), Python 3.13.18 on Linux, 3 side by side, 398 s in all (one version alone: 28.8 to 42.0 s while the others ran). Every app ran in Lantern's test sandbox with no network.

| Version | What is planted | Held | Broken | Undecided | Not run | Broken cases | As written down |
|---|---|---|---|---|---|---|---|
| `safe` | nothing: the safe app | 84 | 0 | 0 | 0 | none | yes |
| `no-login-list` | Anyone can list every note without signing in | 80 | 4 | 0 | 0 | list-hides-other-team/bob (leaked); list-hides-other-team/olga (leaked); list-hides-private/amir (leaked); list-needs-login/nobody (let-in, leaked) | yes |
| `private-note-read` | A teammate can read another person's private note | 83 | 1 | 0 | 0 | private-note/amir (let-in, leaked) | yes |
| `other-team-read` | A member of another team can read a team's note | 79 | 2 | 3 | 0 | other-team-note/bob (let-in, leaked); other-team-note/olga (let-in, leaked) | yes |
| `other-user-change` | Any signed-in person can change another person's note | 82 | 2 | 0 | 0 | note-change/amir (let-in); note-change/olga (let-in) | yes |
| `other-user-delete` | Any signed-in person can delete another person's note | 82 | 2 | 0 | 0 | note-delete/amir (let-in); note-delete/olga (let-in) | yes |
| `refused-but-deleted` | The delete is refused, but the note is already gone | 82 | 2 | 0 | 0 | note-delete/amir (refused-but-changed); note-delete/olga (refused-but-changed) | yes |
| `other-team-list` | The notes of any team can be listed by the team's number | 82 | 2 | 0 | 0 | team-list/alice (leaked); team-list/tara (leaked) | yes |
| `export-every-team` | The export holds every team's notes | 82 | 1 | 1 | 0 | export-hides-other-team/olga (leaked) | yes |
| `member-removes-user` | A regular member can remove a user | 83 | 1 | 0 | 0 | remove-user/alice (let-in) | yes |
| `other-team-admin` | An admin of another team can remove a user | 83 | 1 | 0 | 0 | remove-user/olga (let-in) | yes |
| `expired-token` | A sign-in that has run out still works | 83 | 1 | 0 | 0 | tokens/expired (let-in) | yes |
| `unsigned-token` | A sign-in token that was altered or made up still works | 79 | 5 | 0 | 0 | tokens/altered (let-in); tokens/expired (let-in); tokens/other-key (let-in); tokens/truncated (let-in); tokens/unsigned (let-in) | yes |
| `scope-unchecked` | A token meant for reading only can change things | 81 | 3 | 0 | 0 | note-change/alice_read (let-in); note-delete/alice_read (let-in); read-only-token/alice_read (let-in) | yes |
| `sign-in-remembered` | A removed person's sign-in goes on working on the copy of the app that let them in before | 82 | 2 | 0 | 0 | removed-user/on another worker (lived-on); removed-user/straight after (lived-on) | yes |
| `note-after-removal` | A person removed while their note is on its way still gets the note added | 83 | 1 | 0 | 0 | removed-midway/ended half-way (lived-on) | yes |
| `role-in-profile` | A member can make themself admin through the profile form | 83 | 1 | 0 | 0 | profile-role/the request (took-effect) | yes |
| `negative-transfer` | A negative amount moves credits the wrong way | 83 | 1 | 0 | 0 | negative-transfer/the bad request (accepted) | yes |
| `no-size-limit` | A request of several megabytes is accepted and stored | 81 | 3 | 0 | 0 | huge-file/the bad request (accepted); huge-note-undeclared/the bad request (accepted); huge-note/the bad request (accepted) | yes |
| `upload-name-escapes` | An upload's name can leave the uploads folder | 83 | 1 | 0 | 0 | upload-name/the request (outside-file) | yes |
| `upload-served-as-page` | An uploaded web page is accepted and served back as a page | 82 | 2 | 0 | 0 | upload-page-served/the request (took-effect); upload-page/the bad request (accepted) | yes |
| `zip-entry-escapes` | A name inside a zip can leave the folder it is unpacked into | 83 | 1 | 0 | 0 | zip-names/the request (outside-file) | yes |
| `zip-bomb` | A small zip that unpacks to many megabytes is unpacked in full | 83 | 1 | 0 | 0 | zip-bomb/the bad request (accepted) | yes |
| `open-redirect` | The redirect goes to any address it is given | 82 | 2 | 0 | 0 | go-elsewhere/the request (sent-elsewhere); go-two-slashes/the request (sent-elsewhere) | yes |
| `redirect-half-checked` | The redirect's check lets //another-site through | 83 | 1 | 0 | 0 | go-two-slashes/the request (sent-elsewhere) | yes |
| `fetch-any-address` | The link preview fetches any address, internal ones too | 77 | 7 | 0 | 0 | preview-inside-name/the request (outside-address); preview-internal/the request (outside-address); preview-localhost-caps/the request (outside-address); preview-loopback-number/the request (outside-address); preview-loopback-v6/the request (outside-address); preview-loopback/the request (outside-address); preview-other-site/the request (outside-address) | yes |
| `fetch-half-checked` | The preview's check misses other spellings of internal addresses | 78 | 6 | 0 | 0 | preview-inside-name/the request (outside-address); preview-internal/the request (outside-address); preview-localhost-caps/the request (outside-address); preview-loopback-number/the request (outside-address); preview-loopback-v6/the request (outside-address); preview-other-site/the request (outside-address) | yes |
| `no-login-limit` | Wrong passwords can be tried without end | 81 | 3 | 0 | 0 | login-limit/after a restart (unlimited); login-limit/on another worker (unlimited); login-limit/straight after (unlimited) | yes |
| `limit-in-memory` | The count of wrong passwords is forgotten at a restart and not shared between workers | 82 | 2 | 0 | 0 | login-limit/after a restart (forgotten); login-limit/on another worker (forgotten) | yes |
| `double-spend` | A coupon can be redeemed twice at the same moment | 83 | 1 | 0 | 0 | coupon-once/at the same moment (raced) | yes |
| `no-undo` | A transfer that fails half-way keeps the half that was done | 80 | 8 | 0 | 0 | transfer-failures/the app is cut off before commit 2 (partial); transfer-failures/the app is cut off before commit 3 (partial); transfer-failures/the app is cut off before write 2 (partial); transfer-failures/the app is cut off before write 3 (partial); transfer-failures/the database fails at commit 2 (partial); transfer-failures/the database fails at commit 3 (partial); transfer-failures/the database fails at write 2 (partial); transfer-failures/the database fails at write 3 (partial) | yes |
| `undo-by-hand` | A transfer that is cut off half-way keeps the half that was done | 83 | 3 | 0 | 0 | transfer-failures/the app is cut off before commit 2 (partial); transfer-failures/the app is cut off before write 2 (partial); transfer-failures/the app is cut off before write 3 (partial) | yes |
| `retry-repeats` | The same transfer sent again moves the credits again | 82 | 2 | 0 | 0 | transfer-retry/sent again (repeated); transfer-retry/sent again after the answer was lost (repeated) | yes |
| `shared-connection` | The half of a failed transfer is saved by the next person's request | 79 | 5 | 0 | 0 | remove-user-failures/the database fails at commit 1 (carried-over); remove-user-failures/the database fails at write 2 (carried-over); transfer-failures/the database fails at commit 1 (carried-over); transfer-failures/the database fails at write 2 (carried-over); transfer-failures/the database fails at write 3 (carried-over) | yes |

34 versions, 34 as written down, 0 differing. The whole plan was run against every version, so no other case may come out broken.
