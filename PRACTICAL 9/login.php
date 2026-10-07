<?php
// Practical 9 (companion): Login using password_verify() to prove hashing works
session_start();
require_once 'config.php';

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$errors = [];
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $errors[] = 'Invalid CSRF token.';
    } else {
        $email = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';

        if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = 'Please enter a valid email address.';
        } elseif ($password === '') {
            $errors[] = 'Password is required.';
        } else {
            $stmt = $conn->prepare('SELECT id, username, email, password FROM users WHERE email = ? LIMIT 1');
            $stmt->bind_param('s', $email);
            $stmt->execute();
            $user = $stmt->get_result()->fetch_assoc();
            $stmt->close();

            // password_verify() matches password_hash() from register.php
            if ($user && password_verify($password, $user['password'])) {
                $success = 'Login successful! Welcome back, ' . htmlspecialchars($user['username']) . '.';
                $logStmt = $conn->prepare('INSERT INTO audit_log (user_id, action, details, ip_address) VALUES (?, ?, ?, ?)');
                $action = 'user_login';
                $details = 'User logged in: ' . $user['username'];
                $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
                $logStmt->bind_param('isss', $user['id'], $action, $details, $ip);
                $logStmt->execute();
                $logStmt->close();
            } else {
                $errors[] = 'Invalid email or password.';
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Login — Practical 9</title>
<style>
  * { box-sizing: border-box; font-family: Arial, sans-serif; }
  body { background: #f2f4f8; margin: 0; padding: 20px; }
  .card { max-width: 420px; margin: 30px auto; background: #fff; padding: 28px; border-radius: 10px; box-shadow: 0 2px 12px rgba(0,0,0,.1); }
  h2 { margin-top: 0; text-align: center; }
  label { font-weight: bold; display: block; margin: 12px 0 4px; }
  input { width: 100%; padding: 10px; border: 1px solid #bbb; border-radius: 6px; }
  button { width: 100%; margin-top: 16px; padding: 12px; background: #16a34a; color: #fff; border: none; border-radius: 6px; font-size: 16px; cursor: pointer; }
  button:hover { background: #15803d; }
  .alert-error { background: #fee2e2; color: #991b1b; border: 1px solid #fca5a5; padding: 10px; border-radius: 6px; margin-bottom: 10px; }
  .alert-success { background: #dcfce7; color: #166534; border: 1px solid #86efac; padding: 10px; border-radius: 6px; margin-bottom: 10px; }
  .link { text-align: center; margin-top: 12px; }
</style>
</head>
<body>
<div class="card">
  <h2>Login</h2>
  <?php foreach ($errors as $e): ?>
    <div class="alert-error"><?= htmlspecialchars($e) ?></div>
  <?php endforeach; ?>
  <?php if ($success): ?>
    <div class="alert-success"><?= $success ?></div>
  <?php endif; ?>
  <form method="POST" action="login.php">
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
    <label for="email">Email</label>
    <input type="email" id="email" name="email" required>
    <label for="password">Password</label>
    <input type="password" id="password" name="password" required>
    <button type="submit">Login</button>
  </form>
  <div class="link">No account? <a href="register.php">Register</a></div>
</div>
</body>
</html>
