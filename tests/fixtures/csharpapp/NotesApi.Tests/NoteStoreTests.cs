using NotesApi;
using Xunit;

namespace NotesApi.Tests;

public class NoteStoreTests
{
    [Fact]
    public void FindsNothingWithoutADatabase()
    {
        var store = new NoteStore();
        Assert.Throws<InvalidOperationException>(() => store.Find("1"));
    }
}
