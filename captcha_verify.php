<?php
// ============================================
// captcha_verify.php — CAPTCHA Verification
//
// Step 1 of the login flow. Verifies the user
// is human before showing the login form.
// Generates a simple math question stored in
// session. On pass, sets captcha_passed flag
// and redirects to login.php.
// ============================================

session_start();
require_once 'db.php';

// Prevent caching
header('Cache-Control: no-store, no-cache, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');

// Already logged in — go to dashboard
if (isset($_SESSION['username'])) {
    header("Location: " . ($_SESSION['role'] === 'admin' ? 'admin.php' : 'dashboard.php'));
    exit;
}

// ============================================
// Generate new CAPTCHA if not exists
// ============================================
if (!isset($_SESSION['captcha_answer'])) {
    $num1 = rand(1, 9);
    $num2 = rand(1, 9);
    $_SESSION['captcha_answer'] = $num1 + $num2;
    $_SESSION['captcha_q']      = "$num1 + $num2";
}

$error = '';

// ============================================
// PROCESS the CAPTCHA answer
// ============================================
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $captcha = trim($_POST['captcha'] ?? '');

    if (empty($captcha)) {
        $error = "Please answer the security question.";

    } elseif ((int)$captcha !== (int)$_SESSION['captcha_answer']) {
        // Wrong answer — regenerate CAPTCHA
        $n1 = rand(1, 9);
        $n2 = rand(1, 9);
        $_SESSION['captcha_answer'] = $n1 + $n2;
        $_SESSION['captcha_q']      = "$n1 + $n2";
        $error = "Wrong answer. Please try again.";

    } else {
        // Correct — set flag and proceed to login
        $_SESSION['captcha_passed'] = true;
        unset($_SESSION['captcha_answer'], $_SESSION['captcha_q']);
        header("Location: login.php");
        exit;
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
    <title>Security Check - Code Breaker</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>

<div class="navbar">
    <a href="index.php" class="logo">[ CODE BREAKER ]</a>
    <nav>
        <a href="index.php">&larr; Back to Home</a>
    </nav>
</div>

<div class="page-wrapper">
    <div class="card">

        <div class="card-header">
            <div class="icon"></div>
            <h1>SECURITY CHECK</h1>
            <p>Step 1 of 3 &mdash; Verify you are human</p>
        </div>

        <?php if ($error): ?>
            <div class="alert alert-error"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>

        <form method="POST" action="captcha_verify.php">

            <!-- CAPTCHA — simple addition question -->
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

            <button type="submit" class="btn btn-primary">Verify &rarr;</button>

        </form>

        <p class="form-footer">
            <a href="index.php" class="link-muted">&larr; Start over</a>
        </p>

    </div>
</div>

</body>
</html>
