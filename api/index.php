<?php

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Headers: Content-Type, Authorization');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

include './classes/database.php';
include './classes/jwt.php';

$uri = trim(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH), '/');
$uri = explode('/', $uri);

$action = end($uri);

$bearer_token = get_bearer_token();
$is_jwt_valid = isset($bearer_token) ? is_jwt_valid($bearer_token) : false;

$database = new Database();

function get_json_body()
{
    $rest_json = file_get_contents('php://input');
    $data = json_decode($rest_json, true);
    if (!is_array($data)) {
        return_json(['status' => 0, 'error' => 'Invalid or malformed JSON input']);
    }
    return $data;
}

if ($action === 'register') {
    $_POST = get_json_body();
    $required_fields = ['name', 'lastname', 'username', 'password', 'email'];
    foreach ($required_fields as $field) {
        if (empty($_POST[$field])) {
            return_json(['status' => 0, 'error' => "Missing field: $field"]);
        }
    }
    if ($database->getUserByUsernameOrEmail($_POST['username']) || $database->getUserByUsernameOrEmail($_POST['email'])) {
        return_json(['status' => 0, 'error' => 'User already exists']);
    }

    $user = [
        'name' => $_POST['name'],
        'lastname' => $_POST['lastname'],
        'username' => $_POST['username'],
        'password' => ($_POST['password']),
        // 'password' => md5($_POST['password']),
        'email' => $_POST['email'],
        'status' => 0,
        'created_date' => date('Y-m-d H:i:s'),
    ];

    if ($user_id = $database->register($user)) {
        $user['id'] = $user_id;
        if ($code = $database->generateConfirmCode($user_id)) {
             // send generated code by email to user
            $to = $user['email'];
            $subject = 'Your Confirmation Code';
            $message = "Hello " . $user['name'] . ",\n\nYour confirmation code is: " . $code;
            $headers = 'From: noreply@prephq.theiotacademy.co' . "\r\n" .
                    'Reply-To: noreply@prephq.theiotacademy.co' . "\r\n" .
                    'X-Mailer: PHP/' . phpversion();

            mail($to, $subject, $message, $headers); 

            // Generate JWT
            $headers = ['alg' => 'HS256', 'typ' => 'JWT'];
            $payload = ['user' => $user];
            $jwt = generate_jwt($headers, $payload);
            return_json(['status' => $jwt]);
        }
    }
    return_json(['status' => 0, 'error' => 'Registration failed']);
}

elseif ($action === 'confirm') {
    if ($is_jwt_valid) {
        $_POST = get_json_body();
        if (empty($_POST['code'])) {
            return_json(['status' => 0, 'error' => 'Missing confirmation code']);
        }

        $user_id = getPayload($bearer_token)->user->id;

        if ($database->confirmCode($user_id, $_POST['code'])) {
            if ($database->activeUser($user_id)) {
                return_json(['status' => 1]);
            }
        }
    }
    return_json(['status' => 0, 'error' => 'Invalid token or confirmation failed']);
}

elseif ($action === 'login') {
    $_POST = get_json_body();

    if (empty($_POST['username']) || empty($_POST['password'])) {
        return_json(['status' => 0, 'error' => 'Missing username or password']);
    }

    if (
        $user = $database->loginUser(
            $_POST['username'],
            ($_POST['password'])
            // md5($_POST['password'])
        )
    ) {
        $headers = ['alg' => 'HS256', 'typ' => 'JWT'];
        $payload = ['user' => $user];
        $jwt = generate_jwt($headers, $payload);
        return_json(['status' => 1, 'token' => $jwt]);
    }
    return_json(['status' => 0, 'error' => 'Invalid credentials']);
}

elseif ($action === 'reset') {
    $_POST = get_json_body();
    if (empty($_POST['username'])) {
        return_json(['status' => 0, 'error' => 'Missing username']);
    }

    if ($user = $database->getUserByUsernameOrEmail($_POST['username'])) {
        $generated_password = uniqid();
        $user['password'] = ($generated_password);
        // $user['password'] = md5($generated_password);
        if ($database->updateUser($user)) {
            // Send password to user's email
            $to = $user['email'];
            $subject = 'Your New Password - Prephq IoT';
            $message = "Hello " . $user['name'] . ",\n\nYour new temporary password is: $generated_password\nPlease log in and change it immediately.\n\nRegards,\nSupport Team";
            $headers = "From: support@theiotacademy.co\r\n";
            $headers .= "Reply-To: support@theiotacademy.co\r\n";
            $headers .= "X-Mailer: PHP/" . phpversion();

            if (mail($to, $subject, $message, $headers)) {
                return_json(['status' => 1]);
            } else {
                return_json(['status' => 0, 'error' => 'Failed to send email']);
            }
            // Send password to user's email not addd
            // return_json(['status' => 1]);
        }
    }
    return_json(['status' => 0, 'error' => 'User not found or update failed']);
}

elseif ($action === 'user') {
    if ($is_jwt_valid) {
        $username = getPayload($bearer_token)->user->username;
        if ($user = $database->getUserByUsernameOrEmail($username)) {
            return_json(['status' => 1, 'user' => $user]);
        }
    }
    return_json(['status' => 0, 'error' => 'Invalid token or user not found']);
}

return_json(['status' => 0, 'error' => 'Invalid endpoint']);

function return_json($arr)
{
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Headers: *');
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($arr);
    exit();
}
