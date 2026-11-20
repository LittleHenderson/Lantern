# Behaviour benchmark: the plan Lantern writes by itself, on Corkboard, safe and with each planted problem

`python bench/behaviour/run_behaviour.py WORKDIR --first-plan`, 2026-11-19 (UTC), Python 3.13.18 on Linux, 3 side by side, 195 s in all (one version alone: 15.5 to 17.2 s while the others ran). Every app ran in Lantern's test sandbox with no network.

| Version | What is planted | Checks | Held | Broken | Undecided | Not run | Broken cases | As written down |
|---|---|---|---|---|---|---|---|---|
| `safe` | nothing: the safe app | 16 | 16 | 0 | 6 | 1 | none | yes |
| `no-login-list` | Anyone can list every note without signing in | 16 | 15 | 1 | 6 | 1 | get-notes/nobody (let-in) | yes |
| `private-note-read` | A teammate can read another person's private note | 16 | 16 | 0 | 6 | 1 | none | yes |
| `other-team-read` | A member of another team can read a team's note | 16 | 15 | 1 | 6 | 1 | get-notes-note-id/bob (let-in, leaked) | yes |
| `other-user-change` | Any signed-in person can change another person's note | 16 | 15 | 1 | 6 | 1 | put-notes-note-id/bob (let-in) | yes |
| `other-user-delete` | Any signed-in person can delete another person's note | 16 | 15 | 1 | 6 | 1 | delete-notes-note-id/bob (let-in) | yes |
| `refused-but-deleted` | The delete is refused, but the note is already gone | 16 | 15 | 1 | 6 | 1 | delete-notes-note-id/bob (refused-but-changed) | yes |
| `other-team-list` | The notes of any team can be listed by the team's number | 16 | 15 | 1 | 6 | 1 | get-teams-team-id-notes/bob (let-in) | yes |
| `export-every-team` | The export holds every team's notes | 16 | 16 | 0 | 6 | 1 | none | yes |
| `member-removes-user` | A regular member can remove a user | 16 | 16 | 0 | 6 | 1 | none | yes |
| `other-team-admin` | An admin of another team can remove a user | 16 | 16 | 0 | 6 | 1 | none | yes |
| `expired-token` | A sign-in that has run out still works | 16 | 16 | 0 | 6 | 1 | none | yes |
| `unsigned-token` | A sign-in token that was altered or made up still works | 16 | 16 | 0 | 6 | 1 | none | yes |
| `scope-unchecked` | A token meant for reading only can change things | 16 | 16 | 0 | 6 | 1 | none | yes |
| `sign-in-remembered` | A removed person's sign-in goes on working on the copy of the app that let them in before | 16 | 16 | 0 | 6 | 1 | none | yes |
| `note-after-removal` | A person removed while their note is on its way still gets the note added | 16 | 16 | 0 | 6 | 1 | none | yes |
| `role-in-profile` | A member can make themself admin through the profile form | 16 | 16 | 0 | 6 | 1 | none | yes |
| `negative-transfer` | A negative amount moves credits the wrong way | 16 | 16 | 0 | 6 | 1 | none | yes |
| `no-size-limit` | A request of several megabytes is accepted and stored | 16 | 16 | 0 | 6 | 1 | none | yes |
| `upload-name-escapes` | An upload's name can leave the uploads folder | 16 | 16 | 0 | 6 | 1 | none | yes |
| `upload-served-as-page` | An uploaded web page is accepted and served back as a page | 16 | 16 | 0 | 6 | 1 | none | yes |
| `zip-entry-escapes` | A name inside a zip can leave the folder it is unpacked into | 16 | 16 | 0 | 6 | 1 | none | yes |
| `zip-bomb` | A small zip that unpacks to many megabytes is unpacked in full | 16 | 16 | 0 | 6 | 1 | none | yes |
| `open-redirect` | The redirect goes to any address it is given | 16 | 16 | 0 | 6 | 1 | none | yes |
| `redirect-half-checked` | The redirect's check lets //another-site through | 16 | 16 | 0 | 6 | 1 | none | yes |
| `fetch-any-address` | The link preview fetches any address, internal ones too | 16 | 16 | 0 | 6 | 1 | none | yes |
| `fetch-half-checked` | The preview's check misses other spellings of internal addresses | 16 | 16 | 0 | 6 | 1 | none | yes |
| `no-login-limit` | Wrong passwords can be tried without end | 16 | 13 | 3 | 6 | 1 | limit-post-login/after a restart (unlimited); limit-post-login/on another worker (unlimited); limit-post-login/straight after (unlimited) | yes |
| `limit-in-memory` | The count of wrong passwords is forgotten at a restart and not shared between workers | 16 | 14 | 2 | 6 | 1 | limit-post-login/after a restart (forgotten); limit-post-login/on another worker (forgotten) | yes |
| `double-spend` | A coupon can be redeemed twice at the same moment | 16 | 16 | 0 | 5 | 2 | none | yes |
| `no-undo` | A transfer that fails half-way keeps the half that was done | 16 | 16 | 0 | 6 | 1 | none | yes |
| `undo-by-hand` | A transfer that is cut off half-way keeps the half that was done | 16 | 16 | 0 | 6 | 1 | none | yes |
| `retry-repeats` | The same transfer sent again moves the credits again | 16 | 16 | 0 | 6 | 1 | none | yes |
| `shared-connection` | The half of a failed transfer is saved by the next person's request | 16 | 16 | 0 | 6 | 1 | none | yes |

34 versions, 34 as written down, 0 differing. The plan Lantern wrote by itself catches 8 of the 33 planted problems run here (8 are written down as its to catch: a visitor let in, somebody else's row, wrong passwords not counted); the plan a person wrote (`plan.py`, `results.md`) catches all of them. An undecided case is one whose check the plan named to look at first: Lantern made up a value the app does not take.
