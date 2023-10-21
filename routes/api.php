<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

// temporary removed in order to test the api
// Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
//     return $request->user();
// });

Route::domain(config('app.api_domain'))->group(function () {
    Log::info('api_url',['api_url' => url()->current()]);
    // api routes inside here
    Route::get('/user', function (Request $request) {
        return response()->json([
            'message' => 'Hello World!',
        ], 200);
    });
});

Route::prefix('api')->domain(config('app.admin_domain'))->group(function () {
    Log::info('admin_api', [ 'api_url' => url()->current()] );
    // Migrate routes into this if you want to maintain compatibility.
    Route::get('/user', function (Request $request) {
        return response()->json([
            'message' => 'Hello World!',
        ], 200);
    });
});
