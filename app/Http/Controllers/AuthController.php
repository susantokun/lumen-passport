<?php

namespace App\Http\Controllers;

use Exception;
use App\Models\User;
use Illuminate\Http\Request;

class AuthController extends Controller {

    public function login(Request $request)
    {
        $email = $request->email;
        $password = $request->password;

        if (empty($email) OR empty($password)) {
            return response()->json([
                'status' => 'error',
                'message' => 'You must fill all the fields'
            ]);
        }

        // $client = new Client([
        //     'base_uri' => 'http://localhost:8000',
        //     'defaults' => [
        //         'exceptions' => false
        //     ],
        //     'connect_timeout' => false,
        //     'timeout' => 2.0,
        // ]);

        try {
            $tokenRequest = $request->create(
                config('service.passport.login_endpoint'),
                'POST'
            );

            $tokenRequest->request->add([
                "client_id" => config('service.passport.client_id'),
                "client_secret" => config('service.passport.client_secret'),
                "grant_type" => "password",
                "username" => $request->email,
                "password" => $request->password,
            ]);

            $response = app()->handle($tokenRequest);
            return $response;

        } catch (Exception $e) {
            return response()->json([
                'status' => 'error',
                'message' => $e->getMessage()
            ]);
        }

    }

    public function register(Request $request)
    {
        $name = $request->name;
        $email = $request->email;
        $password = $request->password;

        // Check if field is not empty
        if (empty($name) or empty($email) or empty($password)) {
            return response()->json(['status' => 'error', 'message' => 'You must fill all the fields']);
        }

        // Check if email is valid
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return response()->json(['status' => 'error', 'message' => 'You must enter a valid email']);
        }

        // Check if password is greater than 5 character
        if (strlen($password) < 6) {
            return response()->json(['status' => 'error', 'message' => 'Password should be min 6 character']);
        }

        // Check if user already exist
        if (User::where('email', '=', $email)->exists()) {
            return response()->json(['status' => 'error', 'message' => 'User already exists with this email']);
        }

        try {
            $user = new User();
            $user->name = $name;
            $user->email = $email;
            $user->password = app('hash')->make($password);

            if ($user->save()) {
                // Will call login method
                return $this->login($request);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => 'error', 'message' => $e->getMessage()]);
        }
    }

    public function logout()
    {
        try {
            auth()->user()->tokens()->each(function ($token) {
                $token->delete();
            });

            return response()->json(['status' => 'success', 'message' => 'Logged out successfully']);
        } catch (\Exception $e) {
            return response()->json(['status' => 'error', 'message' => $e->getMessage()]);
        }
    }
}
