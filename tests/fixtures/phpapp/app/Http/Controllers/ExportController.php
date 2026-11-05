<?php

namespace App\Http\Controllers;

class ExportController extends Controller
{
    public function run(string $name)
    {
        $out = shell_exec("zip -r /tmp/$name.zip storage/notes");
        return ['file' => $name . '.zip', 'log' => $out];
    }
}
