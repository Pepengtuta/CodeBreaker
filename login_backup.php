<?php
// ============================================
// login_backup.php — Backup / Legacy Login
//
// Older version of the login page that includes
// the CAPTCHA inline (before it was moved to a
// separate captcha_verify.php step).
//
// Kept for reference. Not linked in the app.
// ============================================

session_start();
require_once 'db.php';

// Prevent caching
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

// Already logged in — redirect away
if (isset($_SESSION['username'])) {
    header("Location: " . ($_SESSION['role'] === 'admin' ? 'admin.php' : 'dashboard.php'));
    exit;
}

$error   = '';
$success = '';

// ============================================
// Generate CAPTCHA if not already set
// ============================================
if (!isset($_SESSION['captcha_answer'])) {
    $num1 = rand(1, 9);
    $num2 = rand(1, 9);
    $_SESSION['captcha_answer'] = $num1 + $num2;
    $_SESSION['captcha_q']      = "$num1 + $num2";
}

// ============================================
// PROCESS FORM
// ============================================
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $captcha  = trim($_POST['captcha'] ?? '');

    // ---- Validate inputs ----
    if (empty($username) || empty($password) || empty($captcha)) {
        $error = "Fields cannot be empty.";

    } elseif ((int)$captcha !== (int)$_SESSION['captcha_answer']) {
        $error = "Wrong answer to the security question. Try again.";
        // Reset CAPTCHA
        unset($_SESSION['captcha_answer'], $_SESSION['captcha_q']);

    } else {
        // ---- Look up user ----
        $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $user = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        if (!$user) {
            log_login($conn, $username, 'FAILED', 'user not found');
            $error = "Invalid credentials."; // Vague on purpose

        } else {
            // ---- Check lockout (escalating durations) ----
            $luTs       = cb_lock_until_timestamp($user['lock_until'] ?? null);
            $inCooldown = ($luTs !== null && $luTs > time());

            if ($inCooldown) {
                $remaining = max(1, (int)ceil($luTs - time()));
                log_login($conn, $username, 'FAILED', 'account locked');
                $error = "Account locked. Try again in $remaining second(s).";

            } else {
                // Reset stale counter after a successful cooldown
                $fe          = (int)$user['failed_attempts'];
                $expiredLock = ($luTs !== null && $luTs <= time());
                if ($fe >= 3 || $expiredLock) {
                    $stmt = $conn->prepare(
                        "UPDATE users SET failed_attempts = 0, lock_until = NULL WHERE id = ?"
                    );
                    $stmt->bind_param("i", $user['id']);
                    $stmt->execute();
                    $stmt->close();
                    $user['failed_attempts'] = 0;
                    $user['lock_until']      = null;
                    $fe = 0;
                }

                // ---- Check password ----
                if (!password_verify($password, $user['password_hash'])) {

                    $new_attempts = $fe + 1;

                    if ($new_attempts >= 3) {
                        // Progressive lockout: tier 0→30s, 1→60s, 2→120s, 3+→240s
                        $tier      = (int)($user['lockout_tier'] ?? 0);
                        $tierIndex = min(max($tier, 0), 3);
                        $durations = [30, 60, 120, 240];
                        $seconds   = $durations[$tierIndex];
                        $newTier   = min($tier + 1, 4);
                        $lock_time = date('Y-m-d H:i:s', time() + $seconds);

                        $stmt = $conn->prepare(
                            "UPDATE users SET failed_attempts = ?, lock_until = ?, lockout_tier = ? WHERE id = ?"
                        );
                        $stmt->bind_param("isii", $new_attempts, $lock_time, $newTier, $user['id']);
                        $stmt->execute();
                        $stmt->close();

                        log_login($conn, $username, 'FAILED', "account locked after 3 attempts ({$seconds}s)");
                        $error = "Too many failed attempts. Account locked for $seconds seconds.";

                    } else {
                        $stmt = $conn->prepare(
                            "UPDATE users SET failed_attempts = ? WHERE id = ?"
                        );
                        $stmt->bind_param("ii", $new_attempts, $user['id']);
                        $stmt->execute();
                        $stmt->close();

                        $left  = 3 - $new_attempts;
                        log_login($conn, $username, 'FAILED', 'wrong password');
                        $error = "Invalid credentials. $left attempt(s) remaining.";
                    }

                } else {
                    // ---- Password correct — set up step 2 ----
                    $stmt = $conn->prepare(
                        "UPDATE users SET failed_attempts = 0, lock_until = NULL, lockout_tier = 0 WHERE id = ?"
                    );
                    $stmt->bind_param("i", $user['id']);
                    $stmt->execute();
                    $stmt->close();

                    $_SESSION['temp_user_id']  = $user['id'];
                    $_SESSION['temp_username'] = $user['username'];
                    $_SESSION['temp_role']     = $user['role'];
                    $_SESSION['pw_verified']   = true;

                    // Reset CAPTCHA for next session
                    unset($_SESSION['captcha_answer'], $_SESSION['captcha_q']);

                    header("Location: security_question.php");
                    exit;
                }
            }
        }
    }

    // Regenerate CAPTCHA after any failed attempt
    if (!empty($error)) {
        $num1 = rand(1, 9);
        $num2 = rand(1, 9);
        $_SESSION['captcha_answer'] = $num1 + $num2;
        $_SESSION['captcha_q']      = "$num1 + $num2";
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
    <meta http-equiv="Pragma" content="no-cache">
    <meta http-equiv="Expires" content="0">
    <title>Login - Code Breaker</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>

<div class="navbar">
    <a href="index.php" class="logo">[ CODE BREAKER ]</a>
    <nav>
        <a href="index.php">Home</a>
    </nav>
</div>

<div class="page-wrapper">
    <div class="card">

        <div class="card-header">
            <div class="icon"></div>
            <h1>SYSTEM LOGIN</h1>
            <p>Step 1 of 2 &mdash; Enter your credentials</p>
        </div>

        <?php if ($error): ?>
            <div class="alert alert-error"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>

        <form method="POST" action="login_backup.php">

            <div class="form-group">
                <label for="username">Username</label>
                <input
                    type="text"
                    id="username"
                    name="username"
                    placeholder="Enter username"
                    value="<?= htmlspecialchars($_POST['username'] ?? '') ?>"
                    autocomplete="off"
                    required
                >
            </div>

            <div class="form-group">
                <label for="password">Password</label>
                <input
                    type="password"
                    id="password"
                    name="password"
                    placeholder="Enter password"
                    required
                >
            </div>

            <!-- Inline CAPTCHA (legacy — now on a separate page) -->
            <div class="captcha-box">
                <span class="captcha-question">
                    What is <?= htmlspecialchars($_SESSION['captcha_q'] ?? '? + ?') ?>?
                </span>
                <input
                    type="number"
                    name="captcha"
                    placeholder="?"
                    min="0"
                    max="99"
                    required
                >
            </div>

            <button type="submit" class="btn btn-primary">
                Verify &rarr;
            </button>

        </form>

        <p class="form-note">
            No self-registration. Contact your administrator for an account.
        </p>

        <p class="form-footer">
            <a href="forgot_password.php" class="link-muted">Forgot your password?</a>
        </p>

    </div>
</div>

</body>
</html>
