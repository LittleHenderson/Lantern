<?php

namespace App\Services;

use GuzzleHttp\Client;
use Illuminate\Support\Facades\DB;

class NoteService
{
    private Client $client;

    public function __construct()
    {
        $this->client = new Client(['verify' => false]);
    }

    public function remove(string $id): void
    {
        DB::table('notes')->where('id', $id)->delete();
    }

    public function mirror(int $id): void
    {
        $this->client->post("https://backup.example.com/notes/$id");
    }
}
