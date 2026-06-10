<?php
// ============================================
// login.php — Login Page (Step 2 of 3)
//
// Handles: form display, password check,
//          lockout enforcement, and logging.
//
// Uses Post-Redirect-Get (PRG) pattern:
// Every failed attempt stores the error in
// session then redirects (GET). This prevents
// the browser from re-submitting on refresh.
//
// Lockout state is always re-verified from the
// DB so an admin unlock takes effect immediately.
// ============================================

session_start();
require_once 'db.php';

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

// Already logged in — go to dashboard
if (isset($_SESSION['username'])) {
    header("Location: " . ($_SESSION['role'] === 'admin' ? 'admin.php' : 'dashboard.php'));
    exit;
}

// ============================================
// FLASH MESSAGE — set by the POST handler below,
// read and cleared on the next GET load.
// This is the PRG pattern in action.
// ============================================
$error = '';
if (isset($_SESSION['login_flash_error'])) {
    $error = $_SESSION['login_flash_error'];
    unset($_SESSION['login_flash_error']);
}

// ============================================
// LOCKOUT STATE — checked on every GET load.
// DB is the source of truth, not the session,
// so admin unlocks are reflected immediately.
// ============================================
$lockout_seconds = 0;

if (isset($_SESSION['lockout_until_ts'], $_SESSION['lockout_username'])) {

    $lk_stmt = $conn->prepare(
        "SELECT lock_until FROM users WHERE username = ? LIMIT 1"
    );
    $lk_stmt->bind_param("s", $_SESSION['lockout_username']);
    $lk_stmt->execute();
    $lk_row = $lk_stmt->get_result()->fetch_assoc();
    $lk_stmt->close();

    $db_still_locked = $lk_row
        && !empty($lk_row['lock_until'])
        && cb_lock_until_timestamp($lk_row['lock_until']) > time();

    if (!$db_still_locked) {
        // Admin unlocked it or timer expired — clear session flags
        unset($_SESSION['lockout_until_ts'], $_SESSION['lockout_username']);
    } else {
        // Still locked — calculate remaining time from DB value
        $db_ts     = cb_lock_until_timestamp($lk_row['lock_until']);
        $remaining = (int)ceil($db_ts - time());
        if ($remaining > 0) {
            $lockout_seconds = $remaining;
        } else {
            unset($_SESSION['lockout_until_ts'], $_SESSION['lockout_username']);
        }
    }
}

// ============================================
// CAPTCHA GUARD — must pass captcha_verify.php
// before reaching the login form
// ============================================
if (!isset($_SESSION['captcha_passed']) || $_SESSION['captcha_passed'] !== true) {
    header("Location: captcha_verify.php");
    exit;
}

// ============================================
// PROCESS FORM — POST handler
// All failures set a flash error and redirect
// back. This handler never renders HTML.
// ============================================
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    // ---- Validate inputs ----
    if (empty($username) || empty($password)) {
        $_SESSION['login_flash_error'] = "Fields cannot be empty.";
        header("Location: login.php");
        exit;
    }

    // ---- Look up user ----
    $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $user = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if (!$user) {
        log_login($conn, $username, 'FAILED', 'user not found');
        $_SESSION['login_flash_error'] = "Invalid credentials.";
        header("Location: login.php");
        exit;
    }

    // ---- Check lockout ----
    $luTs       = cb_lock_until_timestamp($user['lock_until'] ?? null);
    $inCooldown = ($luTs !== null && $luTs > time());

    if ($inCooldown) {
        $_SESSION['lockout_until_ts'] = $luTs;
        $_SESSION['lockout_username'] = $username;
        log_login($conn, $username, 'FAILED', 'account locked');
        header("Location: login.php");
        exit;
    }

    // ---- Reset expired lock counter ----
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

            $_SESSION['lockout_until_ts'] = time() + $seconds;
            $_SESSION['lockout_username'] = $username;
            log_login($conn, $username, 'FAILED', "account locked after 3 attempts ({$seconds}s)");

        } else {
            $stmt = $conn->prepare(
                "UPDATE users SET failed_attempts = ? WHERE id = ?"
            );
            $stmt->bind_param("ii", $new_attempts, $user['id']);
            $stmt->execute();
            $stmt->close();

            $left = 3 - $new_attempts;
            log_login($conn, $username, 'FAILED', 'wrong password');
            $_SESSION['login_flash_error'] = "Invalid credentials. $left attempt(s) remaining.";
        }

        header("Location: login.php");
        exit;
    }

    // ---- Password correct — prepare step 2 ----
    $stmt = $conn->prepare(
        "UPDATE users SET failed_attempts = 0, lock_until = NULL, lockout_tier = 0 WHERE id = ?"
    );
    $stmt->bind_param("i", $user['id']);
    $stmt->execute();
    $stmt->close();

    unset($_SESSION['lockout_until_ts'], $_SESSION['lockout_username']);

    $_SESSION['temp_user_id']  = $user['id'];
    $_SESSION['temp_username'] = $user['username'];
    $_SESSION['temp_role']     = $user['role'];
    $_SESSION['pw_verified']   = true;

    header("Location: security_question.php");
    exit;
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
        <a href="captcha_verify.php">&larr; Back</a>
        <a href="index.php">Home</a>
    </nav>
</div>

<div class="page-wrapper">
    <div class="card">

        <div class="card-header">
            <div class="icon"></div>
            <h1>SYSTEM LOGIN</h1>
            <p>Step 2 of 3 &mdash; Enter your credentials</p>
        </div>

        <!-- Lockout banner — visible while the account is locked -->
        <?php if ($lockout_seconds > 0): ?>
            <div class="alert alert-error" id="lockout-banner">
                Account locked. Try again in
                <strong id="lockout-countdown"><?= $lockout_seconds ?></strong> second(s).
            </div>
        <?php endif; ?>

        <!-- Regular error messages -->
        <?php if ($error): ?>
            <div class="alert alert-error"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>

        <!-- Form is dimmed and disabled while account is locked -->
        <div class="<?= $lockout_seconds > 0 ? 'form-disabled' : '' ?>">
            <form method="POST" action="login.php">

                <div class="form-group">
                    <label for="username">Username</label>
                    <input
                        type="text"
                        id="username"
                        name="username"
                        placeholder="Enter username"
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

                <button type="submit" class="btn btn-primary">
                    Verify &rarr;
                </button>

            </form>
        </div>

        <p class="form-note">
            No self-registration. Contact your administrator for an account.
        </p>

        <p class="form-footer">
            <a href="forgot_password.php" class="link-muted">Forgot your password?</a>
        </p>

    </div>
</div>


<!-- Live lockout countdown — reloads the page when it hits zero -->
<?php if ($lockout_seconds > 0): ?>
<script>
    var seconds = <?= (int)$lockout_seconds ?>;
    var display = document.getElementById('lockout-countdown');
    var banner  = document.getElementById('lockout-banner');

    var timer = setInterval(function () {
        seconds--;
        if (seconds <= 0) {
            clearInterval(timer);
            banner.textContent  = 'Lockout expired. Reloading...';
            banner.className    = 'alert alert-success';
            setTimeout(function () { window.location.reload(); }, 1200);
        } else {
            display.textContent = seconds;
        }
    }, 1000);
</script>
<?php endif; ?>

</body>
</html>
