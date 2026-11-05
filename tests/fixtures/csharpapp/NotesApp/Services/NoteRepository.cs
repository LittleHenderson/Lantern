using SQLite;

namespace NotesApp.Services;

public class LocalNote
{
    public string Id { get; set; } = "";
    public string Title { get; set; } = "";
}

public class NoteRepository
{
    private readonly SQLiteAsyncConnection _db =
        new SQLiteAsyncConnection(Path.Combine(FileSystem.AppDataDirectory, "notes.db3"));

    public async Task OpenShared(Uri uri)
    {
        var id = uri.Query.TrimStart('?').Replace("id=", "");
        var rows = await _db.QueryAsync<LocalNote>("SELECT * FROM notes WHERE id = '" + id + "'");
        await Shell.Current.GoToAsync($"note?id={rows.FirstOrDefault()?.Id}");
    }
}
