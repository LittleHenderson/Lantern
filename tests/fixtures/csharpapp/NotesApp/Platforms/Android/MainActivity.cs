using Android.App;
using Android.Content;
using Android.Content.PM;

namespace NotesApp;

[Activity(Theme = "@style/Maui.SplashTheme", MainLauncher = true, Exported = true)]
[IntentFilter(new[] { Intent.ActionView }, Categories = new[] { Intent.CategoryDefault, Intent.CategoryBrowsable },
    DataScheme = "notes", DataHost = "open")]
public class MainActivity : MauiAppCompatActivity
{
}
