using NotesApp.Services;
using NotesApp.ViewModels;

namespace NotesApp;

public static class MauiProgram
{
    public static MauiApp CreateMauiApp()
    {
        var builder = MauiApp.CreateBuilder();
        builder.UseMauiApp<App>();
        builder.Services.AddSingleton<ApiClient>();
        builder.Services.AddSingleton<NoteRepository>();
        builder.Services.AddTransient<MainViewModel>();
        builder.Services.AddTransient<MainPage>();
        return builder.Build();
    }
}
