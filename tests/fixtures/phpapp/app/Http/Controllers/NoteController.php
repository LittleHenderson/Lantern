<?php

namespace App\Http\Controllers;

use App\Models\Note;
use App\Services\NoteService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class NoteController extends Controller
{
    public function __construct(private NoteService $notes)
    {
    }

    public function index(Request $request)
    {
        $q = $request->input('q');
        return DB::select("SELECT id, title FROM notes WHERE title LIKE '%$q%'");
    }

    public function show(string $id)
    {
        return DB::select('SELECT id, title, body FROM notes WHERE id = ?', [$id]);
    }

    public function store(Request $request)
    {
        $note = Note::create($request->only('title', 'body'));
        $this->notes->mirror($note->id);
        return $note;
    }

    public function destroy(string $id)
    {
        $this->notes->remove($id);
        return response()->noContent();
    }
}
