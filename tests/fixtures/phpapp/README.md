# phpapp

A Laravel API (`app/`, `routes/api.php`) with a small React page (`resources/js/`) and an old plain-PHP page
(`public/legacy/login.php`), with planted problems:

* `NoteController::index` builds SQL with `"... '%$q%'"` from the search box (reached from the React page).
* `NoteController::destroy` deletes with no login check; the React page calls it.
* `ExportController::run` runs a shell command with the request's file name.
* `NoteService` turns off HTTPS certificate checks.
* `public/legacy/login.php` builds SQL from `$_POST`, echoes `$_GET` into the page, and hashes passwords with MD5.
* `resources/views/note.blade.php` prints a note's body with `{!! !!}`.
