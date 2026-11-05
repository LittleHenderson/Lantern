using NotesApi;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers();
builder.Services.AddSingleton<NoteStore>();
builder.Services.AddCors(o => o.AddDefaultPolicy(p => p.AllowAnyOrigin().AllowAnyHeader()));

var app = builder.Build();
app.UseCors();
app.MapControllers();

var api = app.MapGroup("/api");
api.MapGet("/notes/search", (string q, NoteStore store) => store.Search(q));
api.MapGet("/notes/{id}", NoteEndpoints.Get);
api.MapDelete("/notes/{id}", NoteEndpoints.Delete);

app.Run();
