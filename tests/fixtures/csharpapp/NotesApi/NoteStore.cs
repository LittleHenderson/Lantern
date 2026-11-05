using Microsoft.Data.SqlClient;

namespace NotesApi;

public record Note(string Id, string Title, string Body);

public class NoteStore
{
    private readonly string _conn = Environment.GetEnvironmentVariable("NOTES_DB") ?? "";

    public List<Note> Search(string q)
    {
        using var db = new SqlConnection(_conn);
        db.Open();
        var cmd = new SqlCommand($"SELECT id, title, body FROM notes WHERE title LIKE '%{q}%'", db);
        return Read(cmd);
    }

    public Note? Find(string id)
    {
        using var db = new SqlConnection(_conn);
        db.Open();
        var cmd = new SqlCommand("SELECT id, title, body FROM notes WHERE id = @id", db);
        cmd.Parameters.AddWithValue("@id", id);
        return Read(cmd).FirstOrDefault();
    }

    public void Remove(string id)
    {
        using var db = new SqlConnection(_conn);
        db.Open();
        var cmd = new SqlCommand("DELETE FROM notes WHERE id = @id", db);
        cmd.Parameters.AddWithValue("@id", id);
        cmd.ExecuteNonQuery();
    }

    private static List<Note> Read(SqlCommand cmd)
    {
        var list = new List<Note>();
        using var r = cmd.ExecuteReader();
        while (r.Read())
            list.Add(new Note(r.GetString(0), r.GetString(1), r.GetString(2)));
        return list;
    }
}
