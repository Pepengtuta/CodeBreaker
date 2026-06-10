<?php
// ============================================
// forgot_password.php — Step 1: Request OTP
//
// User enters their username and email.
// If they match a non-root account, an OTP
// is generated and sent to that email address.
// On success, redirects to otp_verify.php.
// ============================================

session_start();
require_once 'db.php';
require_once 'mailer.php';

header('Cache-Control: no-store, no-cache, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');

// Already logged in — no need to be here
if (isset($_SESSION['username'])) {
    header("Location: " . ($_SESSION['role'] === 'admin' ? 'admin.php' : 'dashboard.php'));
    exit;
}

$error = '';

// ============================================
// PROCESS FORM
// ============================================
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $username = trim($_POST['username'] ?? '');
    $email    = trim($_POST['email'] ?? '');

    if (empty($username) || empty($email)) {
        $error = "Both fields are required.";

    } else {
        // Look up user by username + email — both must match.
        // Block root admin (id = 1) — they use setup.php instead.
        $stmt = $conn->prepare(
            "SELECT * FROM users WHERE username = ? AND email = ? AND id != 1"
        );
        $stmt->bind_param("ss", $username, $email);
        $stmt->execute();
        $user = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        if (!$user) {
            // Keep vague — don't reveal which field was wrong
            $error = "No account found matching those details.";

        } else {
            // Generate 6-digit OTP, expires in 5 minutes
            $otp        = sprintf("%06d", mt_rand(0, 999999));
            $expiration = date('Y-m-d H:i:s', time() + (5 * 60));

            $stmt = $conn->prepare(
                "UPDATE users SET otp = ?, otp_expiration = ? WHERE id = ?"
            );
            $stmt->bind_param("ssi", $otp, $expiration, $user['id']);
            $stmt->execute();
            $stmt->close();

            // Send OTP email
            send_otp_email($user['email'], $otp);

            // Store in session so otp_verify.php knows who to check
            $_SESSION['reset_user_id'] = $user['id'];
            $_SESSION['reset_email']   = $user['email'];

            header("Location: otp_verify.php");
            exit;
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
    <title>Forgot Password - Code Breaker</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>

<div class="navbar">
    <a href="index.php" class="logo">[ CODE BREAKER ]</a>
    <nav>
        <a href="login.php">&larr; Back to Login</a>
    </nav>
</div>

<div class="page-wrapper">
    <div class="card">

        <div class="card-header">
            <div class="icon"></div>
            <h1>FORGOT PASSWORD</h1>
            <p>Step 1 of 3 &mdash; Verify your identity</p>
        </div>

        <?php if ($error): ?>
            <div class="alert alert-error"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>

        <form method="POST" action="forgot_password.php">

            <div class="form-group">
                <label for="username">Username</label>
                <input
                    type="text"
                    id="username"
                    name="username"
                    placeholder="Enter your username"
                    value="<?= htmlspecialchars($_POST['username'] ?? '') ?>"
                    autocomplete="off"
                    required
                >
            </div>

            <div class="form-group">
                <label for="email">Email Address</label>
                <input
                    type="email"
                    id="email"
                    name="email"
                    placeholder="Enter your registered email"
                    value="<?= htmlspecialchars($_POST['email'] ?? '') ?>"
                    autocomplete="off"
                    required
                >
                <span class="field-hint">Must match the email on your account.</span>
            </div>

            <button type="submit" class="btn btn-primary">
                Send OTP &rarr;
            </button>

        </form>

        <p class="form-footer">
            <a href="login.php" class="link-muted">&larr; Back to Login</a>
        </p>

    </div>
</div>

</body>
</html>
