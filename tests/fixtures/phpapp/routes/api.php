<?php

use App\Http\Controllers\ExportController;
use App\Http\Controllers\NoteController;
use Illuminate\Support\Facades\Route;

Route::get('/notes', [NoteController::class, 'index']);
Route::get('/notes/{id}', [NoteController::class, 'show']);
Route::delete('/notes/{id}', [NoteController::class, 'destroy']);

Route::middleware('auth:sanctum')->group(function () {
    Route::post('/notes', [NoteController::class, 'store']);
    Route::post('/export/{name}', [ExportController::class, 'run']);
});

Route::get('/health', fn () => ['ok' => true]);
