namespace NotesApp.Services;

public class ApiClient
{
    private readonly HttpClient _http;

    public ApiClient()
    {
        var handler = new HttpClientHandler();
        handler.ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) => true;
        _http = new HttpClient(handler) { BaseAddress = new Uri("https://notes.example.com/") };
    }

    public async Task<List<string>> Search(string q)
    {
        var json = await _http.GetStringAsync($"api/notes/search?q={q}");
        return json.Split('\n').ToList();
    }

    public async Task Remove(string id)
    {
        await _http.DeleteAsync("api/notes/" + id);
    }
}
