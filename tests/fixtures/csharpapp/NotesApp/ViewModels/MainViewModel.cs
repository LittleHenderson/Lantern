using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NotesApp.Services;

namespace NotesApp.ViewModels;

public partial class MainViewModel : ObservableObject
{
    private readonly ApiClient _api;
    private readonly Session _session = new Session();

    public MainViewModel(ApiClient api) { _api = api; }

    public async Task Search(string text)
    {
        var found = await _api.Search(text);
        Results = found;
    }

    public Task Delete(string id) => _api.Remove(id);

    [RelayCommand]
    private void SignIn(string token)
    {
        _session.Save(token);
    }

    public List<string> Results { get; set; } = new();
}
