<?php

namespace App\Http\Controllers;


use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{

    public function login(Request $request): JsonResponse
    {
        $result = Auth::attempt($request->all());

        if ($result) {
            return response()->json([
                "message" => "Login Success",
                "data" => [
                    "token" => $result,
                ]
            ]);
        } else {
            return response()->json([
                "message" => "Wrong Credential",
                "data" => []
            ], 400);
        }

    }

    public function me(Request $request): JsonResponse
    {
        $result = Auth::user();
        return response()->json([
            "message" => "Getting Profile",
            "data" => $result
        ]);
    }

}
