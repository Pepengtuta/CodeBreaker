<?php
// ============================================
// setup.php — System Admin Setup / Reset
//
// Use this to create OR reset the root admin
// account (id = 1) at any time.
//
// This account is a SYSTEM account — it will
// NOT appear in the All Users list in admin.php.
//
// LOCALHOST ONLY — cannot be accessed remotely.
// ============================================

// Block non-localhost access
$allowed = ['127.0.0.1', '::1'];
if (!in_array($_SERVER['REMOTE_ADDR'], $allowed)) {
    http_response_code(403);
    die("403 Forbidden — Setup can only be run from localhost.");
}

require_once 'db.php';

$success  = false;
$error    = '';
$is_reset = false;

// Check if a root account already exists
$existing = $conn->query("SELECT id FROM users WHERE id = 1 LIMIT 1");
if ($existing && $existing->num_rows > 0) {
    $is_reset = true;
}

// ============================================
// PROCESS FORM
// ============================================
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $username    = trim($_POST['username'] ?? '');
    $password    = $_POST['password'] ?? '';
    $confirm_pw  = $_POST['confirm_password'] ?? '';
    $sq_question = trim($_POST['sq_question'] ?? '');
    $sq_answer   = trim($_POST['sq_answer'] ?? '');

    // ---- Validate ----
    if (empty($username) || empty($password) || empty($confirm_pw) || empty($sq_question) || empty($sq_answer)) {
        $error = "All fields are required.";

    } elseif ($password !== $confirm_pw) {
        $error = "Passwords do not match.";

    } elseif (strlen($password) < 8 ||
              !preg_match('/[A-Z]/', $password) ||
              !preg_match('/[a-z]/', $password) ||
              !preg_match('/[0-9]/', $password)) {
        $error = "Password must be at least 8 characters and include uppercase, lowercase, and a number.";

    } else {
        // Hash both the password and the security answer
        $pw_hash  = password_hash($password, PASSWORD_BCRYPT);
        $ans_hash = password_hash(strtolower($sq_answer), PASSWORD_BCRYPT);

        // Always wipe id = 1 first — makes this work as both first-time setup AND a reset
        $conn->query("DELETE FROM security_questions WHERE user_id = 1");
        $conn->query("DELETE FROM users WHERE id = 1");

        // Insert root admin with fixed id = 1
        $stmt = $conn->prepare(
            "INSERT INTO users (id, username, password_hash, role) VALUES (1, ?, ?, 'admin')"
        );
        $stmt->bind_param("ss", $username, $pw_hash);
        $stmt->execute();
        $stmt->close();

        // Insert security question
        $stmt = $conn->prepare(
            "INSERT INTO security_questions (user_id, question, answer_hash) VALUES (1, ?, ?)"
        );
        $stmt->bind_param("ss", $sq_question, $ans_hash);
        $stmt->execute();
        $stmt->close();

        $success  = true;
        $is_reset = false;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Setup - Code Breaker</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>

<div class="page-wrapper">
    <div class="card card-setup">

        <div class="card-header">
            <div class="icon"></div>
            <?php if ($success): ?>
                <h1>SETUP COMPLETE</h1>
                <p>Root admin account has been configured.</p>
            <?php elseif ($is_reset): ?>
                <h1>RESET ROOT ADMIN</h1>
                <p>A root account already exists. Fill in the form to replace it.</p>
            <?php else: ?>
                <h1>INITIAL SETUP</h1>
                <p>Create the system administrator account.</p>
            <?php endif; ?>
        </div>

        <?php if ($success): ?>

            <!-- Success state — show a summary of what was set -->
            <div class="alert alert-success">
                Root admin account configured successfully.
            </div>

            <div class="info-row">
                <span class="label">Username</span>
                <span><?= htmlspecialchars($_POST['username']) ?></span>
            </div>
            <div class="info-row">
                <span class="label">Password</span>
                <span class="text-muted">[hidden]</span>
            </div>
            <div class="info-row">
                <span class="label">Security Question</span>
                <span><?= htmlspecialchars($_POST['sq_question']) ?></span>
            </div>
            <div class="info-row">
                <span class="label">Answer</span>
                <span class="text-muted">[hidden]</span>
            </div>

            <div class="alert alert-error alert-mt">
                <strong>Note:</strong> This is a system account — it will not appear
                in the All Users list. Keep your credentials safe.
                If you forget them, just return to this page to reset.
            </div>

            <p class="form-footer">
            <a href="login.php" class="btn btn-primary">
                Go to Login &rarr;
            </a>
            </p>

        <?php else: ?>

            <!-- Setup / reset form -->
            <?php if ($error): ?>
                <div class="alert alert-error"><?= htmlspecialchars($error) ?></div>
            <?php endif; ?>

            <?php if ($is_reset): ?>
                <div class="alert alert-warning">
                    A root admin account already exists. Submitting this form will
                    <strong>permanently replace</strong> it with the credentials below.
                </div>
            <?php endif; ?>

            <form method="POST" action="setup.php">

                <div class="form-group">
                    <label>Admin Username</label>
                    <input
                        type="text"
                        name="username"
                        placeholder="Choose a username"
                        value="<?= htmlspecialchars($_POST['username'] ?? '') ?>"
                        autocomplete="off"
                        required
                    >
                </div>

                <div class="form-group">
                    <label>Password</label>
                    <input
                        type="password"
                        name="password"
                        placeholder="Min 8 chars, upper + lower + number"
                        required
                    >
                </div>

                <div class="form-group">
                    <label>Confirm Password</label>
                    <input
                        type="password"
                        name="confirm_password"
                        placeholder="Repeat password"
                        required
                    >
                </div>

                <div class="form-group">
                    <label>Security Question</label>
                    <input
                        type="text"
                        name="sq_question"
                        placeholder="e.g. What was your first pet's name?"
                        value="<?= htmlspecialchars($_POST['sq_question'] ?? '') ?>"
                        required
                    >
                </div>

                <div class="form-group">
                    <label>Security Answer</label>
                    <input
                        type="text"
                        name="sq_answer"
                        placeholder="Your answer (not case-sensitive)"
                        autocomplete="off"
                        required
                    >
                    <span class="field-hint">
                        Remember this — it is required to complete login.
                        You can always reset it here if forgotten.
                    </span>
                </div>

                <button type="submit" class="btn btn-primary">
                    <?= $is_reset ? 'Reset Admin Account →' : 'Create Admin Account →' ?>
                </button>

            </form>

        <?php endif; ?>

    </div>
</div>

</body>
</html>
