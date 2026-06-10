<?php
// ============================================
// security_question.php — Step 3 of Login
//
// User answers their security question to
// complete the login process. On correct
// answer, session is fully established and
// the user is redirected to their dashboard.
//
// Guard: requires pw_verified = true in session
//        (set by login.php).
// ============================================

session_start();
require_once 'db.php';

// Prevent caching
header('Cache-Control: no-store, no-cache, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');

// Guard — only reachable after password was verified in login.php
if (!isset($_SESSION['pw_verified']) || $_SESSION['pw_verified'] !== true) {
    header("Location: login.php");
    exit;
}

$user_id  = $_SESSION['temp_user_id'];
$username = $_SESSION['temp_username'];
$error    = '';

// Load a random security question for this user
$stmt = $conn->prepare(
    "SELECT * FROM security_questions WHERE user_id = ? ORDER BY RAND() LIMIT 1"
);
$stmt->bind_param("i", $user_id);
$stmt->execute();
$sq = $stmt->get_result()->fetch_assoc();
$stmt->close();

// Edge case: no security question set — auto-pass this step
if (!$sq) {
    $_SESSION['username']  = $_SESSION['temp_username'];
    $_SESSION['role']      = $_SESSION['temp_role'];
    $_SESSION['user_id']   = $_SESSION['temp_user_id'];
    $_SESSION['loginTime'] = time();

    unset(
        $_SESSION['pw_verified'],
        $_SESSION['temp_user_id'],
        $_SESSION['temp_username'],
        $_SESSION['temp_role']
    );

    log_login($conn, $username, 'SUCCESS', 'success (no security question set)');
    header("Location: " . ($_SESSION['role'] === 'admin' ? 'admin.php' : 'dashboard.php'));
    exit;
}

// ============================================
// PROCESS the security question answer
// ============================================
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $answer = $_POST['answer'] ?? '';

    if (empty(trim($answer))) {
        $error = "Fields cannot be empty.";

    } else {
        $normalized = strtolower(trim($answer));

        if (password_verify($normalized, $sq['answer_hash'])) {

            // Correct — complete the login and establish full session
            $_SESSION['username']  = $_SESSION['temp_username'];
            $_SESSION['role']      = $_SESSION['temp_role'];
            $_SESSION['user_id']   = $_SESSION['temp_user_id'];
            $_SESSION['loginTime'] = time();

            unset(
                $_SESSION['pw_verified'],
                $_SESSION['temp_user_id'],
                $_SESSION['temp_username'],
                $_SESSION['temp_role']
            );

            log_login($conn, $username, 'SUCCESS', 'success');

            header("Location: " . ($_SESSION['role'] === 'admin' ? 'admin.php' : 'dashboard.php'));
            exit;

        } else {
            log_login($conn, $username, 'FAILED', 'wrong security answer');
            $error = "Invalid credentials.";
        }
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
    <title>Security Question - Code Breaker</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>

<div class="navbar">
    <a href="index.php" class="logo">[ CODE BREAKER ]</a>
    <nav>
        <a href="login.php">&larr; Back</a>
        <a href="index.php">Home</a>
    </nav>
</div>

<div class="page-wrapper">
    <div class="card">

        <div class="card-header">
            <div class="icon"></div>
            <h1>SECURITY CHECK</h1>
            <p>Step 3 of 3 &mdash; Verifying identity for
                <strong class="text-accent"><?= htmlspecialchars($username) ?></strong>
            </p>
        </div>

        <?php if ($error): ?>
            <div class="alert alert-error"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>

        <form method="POST" action="security_question.php">

            <!-- Security question display -->
            <div class="q-group">
                <small>Security Question</small>
                <p class="question-text">
                    <?= htmlspecialchars($sq['question']) ?>
                </p>
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

            <button type="submit" class="btn btn-primary">
                Confirm Identity &rarr;
            </button>

        </form>

        <p class="form-footer">
            <a href="login.php" class="link-muted">&larr; Start over</a>
        </p>

    </div>
</div>

</body>
</html>
