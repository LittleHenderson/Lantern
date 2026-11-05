<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;

class PruneNotes extends Command
{
    protected $signature = 'notes:prune';

    public function handle(): void
    {
        DB::table('notes')->where('created_at', '<', now()->subYear())->delete();
    }
}
