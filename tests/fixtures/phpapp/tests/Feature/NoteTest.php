<?php

namespace Tests\Feature;

use Tests\TestCase;

class NoteTest extends TestCase
{
    public function test_health_is_ok(): void
    {
        $this->get('/api/health')->assertOk();
    }
}
