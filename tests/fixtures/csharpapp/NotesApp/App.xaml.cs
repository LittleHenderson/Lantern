using NotesApp.Services;

namespace NotesApp;

public partial class App : Application
{
    private readonly NoteRepository _notes;

    public App(NoteRepository notes)
    {
        InitializeComponent();
        _notes = notes;
        MainPage = new AppShell();
    }

    protected override async void OnAppLinkRequestReceived(Uri uri)
    {
        base.OnAppLinkRequestReceived(uri);
        await _notes.OpenShared(uri);
    }
}
