using NotesApp.ViewModels;

namespace NotesApp;

public partial class MainPage : ContentPage
{
    private readonly MainViewModel _vm;

    public MainPage(MainViewModel vm)
    {
        InitializeComponent();
        BindingContext = _vm = vm;
    }

    private async void OnSearchClicked(object sender, EventArgs e)
    {
        await _vm.Search(SearchBox.Text);
    }

    private async void OnDeleteClicked(object sender, EventArgs e)
    {
        await _vm.Delete(SelectedId);
    }

    private string SelectedId => (string)DeleteButton.CommandParameter;
}
