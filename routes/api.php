<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::post('auth/register', [App\Http\Controllers\Api\Auth\AuthController::class, 'register']);
Route::post('auth/login', [App\Http\Controllers\Api\Auth\AuthController::class, 'login']);

Route::group(['middleware' => ['auth:sanctum']], function () {
    Route::get('auth/me', [App\Http\Controllers\Api\Auth\AuthController::class, 'me']);
    Route::post('auth/logout', [App\Http\Controllers\Api\Auth\AuthController::class, 'logout']);
});
