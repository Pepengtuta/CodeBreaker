<?php
// ============================================
// reset_password.php — Step 3: Reset Password
//
// User answers their security question then
// sets a new password. Both must pass before
// the password is actually changed.
//
// Guard: requires otp_verified = true in session
//        (set by otp_verify.php).
// ============================================

session_start();
require_once 'db.php';

header('Cache-Control: no-store, no-cache, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');

// Guard — only reachable after OTP was verified
if (!isset($_SESSION['otp_verified']) || $_SESSION['otp_verified'] !== true) {
    header("Location: forgot_password.php");
    exit;
}

$user_id = (int)$_SESSION['reset_user_id'];
$error   = '';
$success = false;

// Load the security question for this user
$stmt = $conn->prepare(
    "SELECT * FROM security_questions WHERE user_id = ? ORDER BY RAND() LIMIT 1"
);
$stmt->bind_param("i", $user_id);
$stmt->execute();
$sq = $stmt->get_result()->fetch_assoc();
$stmt->close();

// ============================================
// PROCESS FORM
// ============================================
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $answer  = trim($_POST['answer'] ?? '');
    $new_pw  = $_POST['new_password'] ?? '';
    $conf_pw = $_POST['confirm_password'] ?? '';

    // ---- Validate all fields ----
    if (empty($answer) || empty($new_pw) || empty($conf_pw)) {
        $error = "All fields are required.";

    } elseif (!$sq || !password_verify(strtolower($answer), $sq['answer_hash'])) {
        $error = "Security answer is incorrect.";

    } elseif ($new_pw !== $conf_pw) {
        $error = "Passwords do not match.";

    } elseif (strlen($new_pw) < 8 ||
              !preg_match('/[A-Z]/', $new_pw) ||
              !preg_match('/[a-z]/', $new_pw) ||
              !preg_match('/[0-9]/', $new_pw)) {
        $error = "Password must be at least 8 characters and include uppercase, lowercase, and a number.";

    } else {
        // All checks passed — hash and save the new password
        $new_hash = password_hash($new_pw, PASSWORD_BCRYPT);

        $stmt = $conn->prepare("UPDATE users SET password_hash = ? WHERE id = ?");
        $stmt->bind_param("si", $new_hash, $user_id);
        $stmt->execute();
        $stmt->close();

        // Clean up the entire reset session chain
        unset(
            $_SESSION['reset_user_id'],
            $_SESSION['reset_email'],
            $_SESSION['otp_verified']
        );

        $success = true;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
    <title>Reset Password - Code Breaker</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>

<div class="navbar">
    <a href="index.php" class="logo">[ CODE BREAKER ]</a>
    <nav>
        <a href="login.php">Login</a>
    </nav>
</div>

<div class="page-wrapper">
    <div class="card">

        <div class="card-header">
            <div class="icon"></div>
            <?php if ($success): ?>
                <h1>PASSWORD RESET</h1>
                <p>Your password has been updated.</p>
            <?php else: ?>
                <h1>RESET PASSWORD</h1>
                <p>Step 3 of 3 &mdash; Answer your security question and set a new password</p>
            <?php endif; ?>
        </div>

        <?php if ($success): ?>

            <!-- Success state -->
            <div class="alert alert-success">
                Your password was reset successfully. You can now log in with your new password.
            </div>

            <a href="login.php" class="btn btn-primary">
                Go to Login &rarr;
            </a>

        <?php else: ?>

            <!-- Reset form -->
            <?php if ($error): ?>
                <div class="alert alert-error"><?= htmlspecialchars($error) ?></div>
            <?php endif; ?>

            <form method="POST" action="reset_password.php">

                <!-- Security question display -->
                <?php if ($sq): ?>
                    <div class="form-group">
                        <label>Security Question</label>
                        <div class="question-display">
                            <?= htmlspecialchars($sq['question']) ?>
                        </div>
                    </div>

                    <div class="form-group">
                        <label for="answer">Your Answer</label>
                        <input
                            type="text"
                            id="answer"
                            name="answer"
                            placeholder="Type your answer..."
                            autocomplete="off"
                            required
                        >
                        <span class="field-hint">Not case-sensitive. Spaces are ignored.</span>
                    </div>

                <?php else: ?>
                    <!-- No security question set — skip that check -->
                    <input type="hidden" name="answer" value="__no_sq__">
                    <p class="no-sq-note">No security question is set on this account.</p>
                <?php endif; ?>

                <div class="form-group">
                    <label for="new_password">New Password</label>
                    <input
                        type="password"
                        id="new_password"
                        name="new_password"
                        placeholder="Min 8 chars, upper + lower + number"
                        required
                    >
                </div>

                <div class="form-group">
                    <label for="confirm_password">Confirm New Password</label>
                    <input
                        type="password"
                        id="confirm_password"
                        name="confirm_password"
                        placeholder="Repeat new password"
                        required
                    >
                </div>

                <button type="submit" class="btn btn-primary">
                    Reset Password &rarr;
                </button>

            </form>

        <?php endif; ?>

    </div>
</div>

</body>
</html>
