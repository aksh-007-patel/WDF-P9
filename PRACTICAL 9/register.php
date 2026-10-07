<?php
// Practical 9: Secure User Registration with Database Insert,
// Duplicate Email Check, and Password Hashing
session_start();
require_once 'config.php';

// ---- CSRF token (Advanced extension) ----
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$errors = [];
$success = '';
// Preserve entered values on error
$old = ['username' => '', 'email' => ''];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // 1. CSRF validation
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $errors[] = 'Invalid CSRF token. Please reload the form and try again.';
    } else {
        $username = trim($_POST['username'] ?? '');
        $email    = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        $confirm  = $_POST['confirm_password'] ?? '';

        $old['username'] = $username;
        $old['email'] = $email;

        // 2. Backend validation (must match frontend JS rules below)
        // Username: 3-20 chars, letters/numbers/underscore only
        if ($username === '') {
            $errors[] = 'Username is required.';
        } elseif (!preg_match('/^[A-Za-z0-9_]{3,20}$/', $username)) {
            $errors[] = 'Username must be 3-20 characters (letters, numbers, underscore only).';
        }

        // Email: valid format, max 100 chars
        if ($email === '') {
            $errors[] = 'Email is required.';
        } elseif (strlen($email) > 100 || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = 'Please enter a valid email address.';
        }

        // Password: min 8 chars, at least 1 upper, 1 lower, 1 digit, 1 special
        if ($password === '') {
            $errors[] = 'Password is required.';
        } elseif (strlen($password) < 8) {
            $errors[] = 'Password must be at least 8 characters long.';
        } elseif (!preg_match('/[A-Z]/', $password)
               || !preg_match('/[a-z]/', $password)
               || !preg_match('/[0-9]/', $password)
               || !preg_match('/[^A-Za-z0-9]/', $password)) {
            $errors[] = 'Password must contain at least one uppercase letter, one lowercase letter, one digit and one special character.';
        } elseif ($password !== $confirm) {
            $errors[] = 'Password and Confirm Password do not match.';
        }

        // 3. Duplicate email/username check (Intermediate: prepared statement)
        if (empty($errors)) {
            $stmt = $conn->prepare('SELECT id, username, email FROM users WHERE email = ? OR username = ? LIMIT 1');
            $stmt->bind_param('ss', $email, $username);
            $stmt->execute();
            $result = $stmt->get_result();
            if ($row = $result->fetch_assoc()) {
                if (strcasecmp($row['email'], $email) === 0) {
                    $errors[] = 'This email is already registered. Try logging in instead.';
                } else {
                    $errors[] = 'This username is already taken. Please choose another.';
                }
            }
            $stmt->close();
        }

        // 4. Hash + Insert (prepared statement)
        if (empty($errors)) {
            // Key Q1: password_hash() MUST be used before storing passwords
            $hash = password_hash($password, PASSWORD_DEFAULT);

            $stmt = $conn->prepare('INSERT INTO users (username, email, password) VALUES (?, ?, ?)');
            $stmt->bind_param('sss', $username, $email, $hash);
            $stmt->execute();
            $newUserId = $stmt->insert_id;
            $stmt->close();

            // 5. Audit log entry (Advanced extension)
            $action = 'user_register';
            $details = 'New user registered: ' . $username . ' (' . $email . ')';
            $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
            $logStmt = $conn->prepare('INSERT INTO audit_log (user_id, action, details, ip_address) VALUES (?, ?, ?, ?)');
            $logStmt->bind_param('isss', $newUserId, $action, $details, $ip);
            $logStmt->execute();
            $logStmt->close();

            $success = 'Registration successful! Welcome, ' . htmlspecialchars($username) . '. You can now <a href="login.php">login here</a>.';
            $old = ['username' => '', 'email' => ''];
            // Regenerate CSRF token after successful submission
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Practical 9 — Secure User Registration</title>
<style>
  * { box-sizing: border-box; font-family: Arial, sans-serif; }
  body { background: #f2f4f8; margin: 0; padding: 20px; }
  .card { max-width: 460px; margin: 30px auto; background: #fff; padding: 28px; border-radius: 10px; box-shadow: 0 2px 12px rgba(0,0,0,.1); }
  h2 { margin-top: 0; text-align: center; }
  label { font-weight: bold; display: block; margin: 12px 0 4px; }
  input { width: 100%; padding: 10px; border: 1px solid #bbb; border-radius: 6px; }
  input:focus { outline: none; border-color: #2563eb; }
  .error-text { color: #b91c1c; font-size: 13px; margin-top: 3px; min-height: 16px; }
  .alert-error { background: #fee2e2; color: #991b1b; border: 1px solid #fca5a5; padding: 10px; border-radius: 6px; margin-bottom: 10px; }
  .alert-success { background: #dcfce7; color: #166534; border: 1px solid #86efac; padding: 10px; border-radius: 6px; margin-bottom: 10px; }
  button { width: 100%; margin-top: 16px; padding: 12px; background: #2563eb; color: #fff; border: none; border-radius: 6px; font-size: 16px; cursor: pointer; }
  button:hover { background: #1d4ed8; }
  .link { text-align: center; margin-top: 12px; }
</style>
</head>
<body>
<div class="card">
  <h2>User Registration</h2>

  <?php foreach ($errors as $e): ?>
    <div class="alert-error"><?= htmlspecialchars($e) ?></div>
  <?php endforeach; ?>
  <?php if ($success): ?>
    <div class="alert-success"><?= $success ?></div>
  <?php endif; ?>

  <form id="regForm" method="POST" action="register.php" novalidate>
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">

    <label for="username">Username</label>
    <input type="text" id="username" name="username" maxlength="20"
           value="<?= htmlspecialchars($old['username']) ?>" required>
    <div class="error-text" id="err-username"></div>

    <label for="email">Email</label>
    <input type="email" id="email" name="email" maxlength="100"
           value="<?= htmlspecialchars($old['email']) ?>" required>
    <div class="error-text" id="err-email"></div>

    <label for="password">Password</label>
    <input type="password" id="password" name="password" required>
    <div class="error-text" id="err-password"></div>

    <label for="confirm_password">Confirm Password</label>
    <input type="password" id="confirm_password" name="confirm_password" required>
    <div class="error-text" id="err-confirm"></div>

    <button type="submit">Register</button>
  </form>
  <div class="link">Already registered? <a href="login.php">Login</a></div>
</div>

<script>
// Frontend validation — rules mirror the backend PHP checks (Key Q3)
document.getElementById('regForm').addEventListener('submit', function (e) {
  let valid = true;
  const username = document.getElementById('username').value.trim();
  const email = document.getElementById('email').value.trim();
  const password = document.getElementById('password').value;
  const confirm = document.getElementById('confirm_password').value;

  const setErr = (id, msg) => {
    document.getElementById(id).textContent = msg;
    if (msg) valid = false;
  };

  setErr('err-username', '');
  setErr('err-email', '');
  setErr('err-password', '');
  setErr('err-confirm', '');
  // reset valid flag logic: setErr sets false on msg; re-evaluate cleanly
  valid = true;

  if (!username) { setErr('err-username', 'Username is required.'); }
  else if (!/^[A-Za-z0-9_]{3,20}$/.test(username)) { setErr('err-username', 'Username must be 3-20 characters (letters, numbers, underscore only).'); }

  if (!email) { setErr('err-email', 'Email is required.'); }
  else if (email.length > 100 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) { setErr('err-email', 'Please enter a valid email address.'); }

  if (!password) { setErr('err-password', 'Password is required.'); }
  else if (password.length < 8) { setErr('err-password', 'Password must be at least 8 characters long.'); }
  else if (!/[A-Z]/.test(password) || !/[a-z]/.test(password) || !/[0-9]/.test(password) || !/[^A-Za-z0-9]/.test(password)) {
    setErr('err-password', 'Password must contain uppercase, lowercase, digit and special character.');
  }

  if (password !== confirm) { setErr('err-confirm', 'Password and Confirm Password do not match.'); }

  // recount: if any error text present, block submit
  const anyErr = ['err-username','err-email','err-password','err-confirm']
    .some(id => document.getElementById(id).textContent !== '');
  if (anyErr) e.preventDefault();
});
</script>
</body>
</html>
