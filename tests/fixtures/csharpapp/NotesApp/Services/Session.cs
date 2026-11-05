using System.Diagnostics;

namespace NotesApp.Services;

public class Session
{
    public void Save(string token)
    {
        Preferences.Default.Set("auth_token", token);
        Debug.WriteLine($"Signed in with token {token}");
    }
}
