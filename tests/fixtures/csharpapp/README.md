# csharpapp

A tiny ASP.NET Core API (`NotesApi/`) and a .NET MAUI phone app (`NotesApp/`) that calls it, with planted problems:

* `NotesApi/NoteStore.cs` builds SQL with `$"…{q}…"` from the search box (reached from the phone's search screen).
* `NotesApi/Controllers/ExportController.cs` starts a shell program with text from the request, and uses MD5.
* `NotesApp/Services/NoteRepository.cs` builds a SQLite query from a shared link's text (reached from `OnAppLinkRequestReceived`).
* `NotesApp/Services/Session.cs` keeps the login token in `Preferences` and logs it; `NotesApp/Services/ApiClient.cs` accepts any certificate.
* `NotesApi/Program.cs` allows any website to call the API.
