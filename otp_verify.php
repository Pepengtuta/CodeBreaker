<?php
// ============================================
// otp_verify.php — Step 2: Verify OTP
//
// User enters the 6-digit OTP sent to their
// email. Has a live countdown timer and a
// resend button that appears when the OTP
// expires.
//
// Guard: requires reset_user_id in session
//        (set by forgot_password.php).
// ============================================

session_start();
require_once 'db.php';
require_once 'mailer.php';

header('Cache-Control: no-store, no-cache, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');

// Guard — only reachable after forgot_password.php sets the session
if (!isset($_SESSION['reset_user_id'])) {
    header("Location: forgot_password.php");
    exit;
}

$user_id = (int)$_SESSION['reset_user_id'];
$email   = $_SESSION['reset_email'] ?? '';
$error   = '';

// Load current OTP expiration to drive the countdown timer
$stmt = $conn->prepare("SELECT otp_expiration FROM users WHERE id = ?");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$row = $stmt->get_result()->fetch_assoc();
$stmt->close();

$expiration_ts     = $row['otp_expiration'] ? strtotime($row['otp_expiration']) : 0;
$seconds_remaining = max(0, $expiration_ts - time());

// ============================================
// HANDLE RESEND REQUEST
// Only allowed once the current OTP is expired
// ============================================
if (isset($_GET['resend']) && $_GET['resend'] === 'true') {

    if ($seconds_remaining > 0) {
        // OTP still valid — reject the resend and stay on page
        header("Location: otp_verify.php");
        exit;
    }

    $new_otp        = sprintf("%06d", mt_rand(0, 999999));
    $new_expiration = date('Y-m-d H:i:s', time() + (5 * 60));

    $stmt = $conn->prepare(
        "UPDATE users SET otp = ?, otp_expiration = ? WHERE id = ?"
    );
    $stmt->bind_param("ssi", $new_otp, $new_expiration, $user_id);
    $stmt->execute();
    $stmt->close();

    send_otp_email($email, $new_otp, 'Code Breaker — Your Password Reset OTP (Resent)');

    header("Location: otp_verify.php");
    exit;
}

// ============================================
// PROCESS OTP FORM
// ============================================
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $entered_otp = trim($_POST['otp'] ?? '');

    if (empty($entered_otp)) {
        $error = "Please enter the OTP.";

    } else {
        $stmt = $conn->prepare(
            "SELECT otp, otp_expiration FROM users WHERE id = ?"
        );
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $row = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        $stored_otp = $row['otp'] ?? null;
        $expired    = !$row['otp_expiration'] || strtotime($row['otp_expiration']) <= time();

        if ($expired) {
            $error = "This OTP has expired. Please request a new one using the Resend button.";

        } elseif ($entered_otp !== $stored_otp) {
            $error = "Incorrect OTP. Please try again.";

        } else {
            // Correct — clear OTP from DB and proceed to password reset
            $stmt = $conn->prepare(
                "UPDATE users SET otp = NULL, otp_expiration = NULL WHERE id = ?"
            );
            $stmt->bind_param("i", $user_id);
            $stmt->execute();
            $stmt->close();

            $_SESSION['otp_verified'] = true;

            header("Location: reset_password.php");
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
    <title>Verify OTP - Code Breaker</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>

<div class="navbar">
    <a href="index.php" class="logo">[ CODE BREAKER ]</a>
    <nav>
        <a href="forgot_password.php">&larr; Start Over</a>
    </nav>
</div>

<div class="page-wrapper">
    <div class="card">

        <div class="card-header">
            <div class="icon"></div>
            <h1>VERIFY OTP</h1>
            <p>Step 2 of 3 &mdash; Enter the code sent to your email</p>
        </div>

        <?php if ($error): ?>
            <div class="alert alert-error"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>

        <!-- Show masked email so the user knows where to look -->
        <p class="otp-hint">
            A 6-digit code was sent to
            <strong>
                <?php
                // Mask email: jo***@gmail.com
                $parts  = explode('@', $email);
                $masked = substr($parts[0], 0, 2) . str_repeat('*', max(3, strlen($parts[0]) - 2));
                echo htmlspecialchars($masked . '@' . ($parts[1] ?? ''));
                ?>
            </strong>
        </p>

        <form method="POST" action="otp_verify.php">

            <div class="form-group">
                <label for="otp">One-Time Password</label>
                <input
                    type="text"
                    id="otp"
                    name="otp"
                    class="otp-input"
                    placeholder="000000"
                    maxlength="6"
                    pattern="[0-9]{6}"
                    inputmode="numeric"
                    autocomplete="one-time-code"
                    autofocus
                    required
                >
            </div>

            <button type="submit" class="btn btn-primary">
                Confirm OTP &rarr;
            </button>

        </form>

        <!-- Resend area — shows countdown while OTP is live, link after it expires -->
        <div class="resend-area">
            <?php if ($seconds_remaining > 0): ?>
                <span id="resend-area" class="resend-text">
                    Resend OTP in <span id="countdown"><?= $seconds_remaining ?></span>s
                </span>
            <?php else: ?>
                <span id="resend-area">
                    <a href="otp_verify.php?resend=true" class="resend-link">Resend OTP</a>
                </span>
            <?php endif; ?>
        </div>

        <p class="form-footer">
            <a href="forgot_password.php" class="link-muted">&larr; Use a different account</a>
        </p>

    </div>
</div>


<script>
    // Countdown timer — when it hits 0, replace text with the resend link
    var seconds   = <?= (int)$seconds_remaining ?>;
    var countdown = document.getElementById('countdown');
    var area      = document.getElementById('resend-area');

    if (seconds > 0 && countdown) {
        var timer = setInterval(function () {
            seconds--;
            if (seconds <= 0) {
                clearInterval(timer);
                area.innerHTML = '<a href="otp_verify.php?resend=true" class="resend-link">Resend OTP</a>';
            } else {
                countdown.textContent = seconds;
            }
        }, 1000);
    }
</script>

</body>
</html>
