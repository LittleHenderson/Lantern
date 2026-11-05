namespace NotesApi;

public static class NoteEndpoints
{
    public static Note? Get(string id, NoteStore store) => store.Find(id);

    public static IResult Delete(string id, NoteStore store)
    {
        store.Remove(id);
        return Results.NoContent();
    }
}
