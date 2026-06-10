<?php
// ============================================
// dashboard.php — Regular User Dashboard
//
// Shows the logged-in user's profile info,
// and lets them update their email or password.
// Admin users are redirected to admin.php.
// ============================================

session_start();
require_once 'db.php';

// Prevent caching of protected pages
header('Cache-Control: no-store, no-cache, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');

// ---- Session Guard ----
// If not logged in, redirect to login
if (!isset($_SESSION['username'])) {
    header("Location: login.php");
    exit;
}

// ---- Session Expiration (30 minutes) ----
$session_limit = 30 * 60;
if (isset($_SESSION['loginTime']) && (time() - $_SESSION['loginTime']) > $session_limit) {
    // Session expired — log them out
    session_destroy();
    header("Location: login.php?msg=expired");
    exit;
}

// ---- Role Check ----
// Only 'user' role should be here — admins get redirected
if ($_SESSION['role'] === 'admin') {
    header("Location: admin.php");
    exit;
}

// Get the current user's info
$stmt = $conn->prepare('SELECT * FROM users WHERE username = ?');
$stmt->bind_param('s', $_SESSION['username']);
$stmt->execute();
$user = $stmt->get_result()->fetch_assoc();
$stmt->close();

// ============================================
// Handle Email Update
// ============================================
$email_error   = '';
$email_success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_email'])) {

    $new_email = trim($_POST['new_email'] ?? '');

    if (empty($new_email)) {
        // Allow clearing the email
        $stmt = $conn->prepare("UPDATE users SET email = NULL WHERE id = ?");
        $stmt->bind_param("i", $user['id']);
        $stmt->execute();
        $stmt->close();
        $email_success = "Email removed from your account.";

    } elseif (!filter_var($new_email, FILTER_VALIDATE_EMAIL)) {
        $email_error = "Please enter a valid email address.";

    } else {
        $stmt = $conn->prepare("UPDATE users SET email = ? WHERE id = ?");
        $stmt->bind_param("si", $new_email, $user['id']);
        $stmt->execute();
        $stmt->close();
        log_action($conn, $_SESSION['username'], 'updated email address');
        $email_success = "Email updated successfully.";
    }

    // Refresh user data after update
    $stmt = $conn->prepare('SELECT * FROM users WHERE id = ?');
    $stmt->bind_param("i", $user['id']);
    $stmt->execute();
    $user = $stmt->get_result()->fetch_assoc();
    $stmt->close();
}

// ============================================
// Handle Password Change
// ============================================
$pw_error   = '';
$pw_success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['change_password'])) {

    $old_pw  = $_POST['old_password'] ?? '';
    $new_pw  = $_POST['new_password'] ?? '';
    $conf_pw = $_POST['confirm_password'] ?? '';

    if (empty($old_pw) || empty($new_pw) || empty($conf_pw)) {
        $pw_error = "Fields cannot be empty.";

    } elseif (!password_verify($old_pw, $user['password_hash'])) {
        $pw_error = "Current password is incorrect.";

    } elseif ($new_pw !== $conf_pw) {
        $pw_error = "New passwords do not match.";

    } elseif (strlen($new_pw) < 8 ||
              !preg_match('/[A-Z]/', $new_pw) ||
              !preg_match('/[a-z]/', $new_pw) ||
              !preg_match('/[0-9]/', $new_pw)) {
        $pw_error = "Password must be at least 8 characters and include uppercase, lowercase, and a number.";

    } else {
        // Hash and save the new password
        $new_hash = password_hash($new_pw, PASSWORD_BCRYPT);
        $stmt = $conn->prepare("UPDATE users SET password_hash = ? WHERE id = ?");
        $stmt->bind_param("si", $new_hash, $user['id']);
        $stmt->execute();
        $stmt->close();

        log_action($conn, $_SESSION['username'], 'changed password');
        $pw_success = "Password changed successfully!";

        // Refresh user data after update
        $stmt = $conn->prepare('SELECT * FROM users WHERE id = ?');
        $stmt->bind_param("i", $user['id']);
        $stmt->execute();
        $user = $stmt->get_result()->fetch_assoc();
        $stmt->close();
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
    <title>Dashboard - Code Breaker</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>

<!-- Navbar -->
<div class="navbar">
    <a href="index.php" class="logo">[ CODE BREAKER ]</a>
    <nav>
        <a href="dashboard.php" class="active">Dashboard</a>
        <a href="logout.php">Logout</a>
    </nav>
</div>

<div class="dashboard">

    <!-- Header -->
    <div class="dashboard-header">
        <div>
            <h1>User Dashboard</h1>
            <p>Welcome back, <strong><?= htmlspecialchars($user['username']) ?></strong></p>
        </div>
        <a href="logout.php" class="btn btn-outline btn-sm">Logout</a>
    </div>

    <!-- ---- Account Info ---- -->
    <div class="card card-full">

        <!-- Title + toggle buttons on the same line -->
        <div class="card-actions-header">
            <p class="section-title">Account Information</p>
            <div class="btn-group">
                <button type="button" class="btn btn-outline btn-sm"
                        onclick="toggleSection('email-section')">
                    Update Email
                </button>
                <button type="button" class="btn btn-outline btn-sm"
                        onclick="toggleSection('password-section')">
                    Change Password
                </button>
            </div>
        </div>

        <!-- Account Details (always visible) -->
        <div class="info-row">
            <span class="label">Username</span>
            <span><?= htmlspecialchars($user['username']) ?></span>
        </div>
        <div class="info-row">
            <span class="label">Email</span>
            <span>
                <?php if (!empty($user['email'])): ?>
                    <?= htmlspecialchars($user['email']) ?>
                <?php else: ?>
                    <span class="text-muted-sm">Not set</span>
                <?php endif; ?>
            </span>
        </div>
        <div class="info-row">
            <span class="label">Role</span>
            <span class="badge badge-user"><?= strtoupper($user['role']) ?></span>
        </div>
        <div class="info-row">
            <span class="label">Account Created</span>
            <span><?= $user['created_at'] ?></span>
        </div>
        <div class="info-row">
            <span class="label">Failed Login Attempts</span>
            <span><?= (int)$user['failed_attempts'] ?></span>
        </div>
        <div class="info-row">
            <span class="label">Account Status</span>
            <?php $acct_locked = cb_user_login_cooldown_active($user['lock_until'] ?? null); ?>
            <span class="badge <?= $acct_locked ? 'badge-locked' : 'badge-success' ?>">
                <?= $acct_locked ? 'Locked' : 'Active' ?>
            </span>
        </div>
        <div class="info-row">
            <span class="label">Session Started</span>
            <span><?= date('Y-m-d H:i:s', $_SESSION['loginTime']) ?></span>
        </div>

        <!-- Email Form (hidden by default) -->
        <div id="email-section" class="toggle-section">
            <form method="POST">
                <div class="form-group">
                    <label>Email Address</label>
                    <input
                        type="email"
                        name="new_email"
                        placeholder="Enter your email address"
                        value="<?= htmlspecialchars($user['email'] ?? '') ?>"
                    >
                    <span class="field-hint">Leave blank to remove your email from this account.</span>
                </div>
                <div class="form-actions">
                    <button type="submit" name="update_email" class="btn btn-primary btn-flex">
                        Save Email
                    </button>
                    <button type="button" class="btn btn-outline"
                            onclick="toggleSection('email-section')">
                        Cancel
                    </button>
                </div>
            </form>
            <?php if ($email_error): ?>
                <div class="alert alert-error alert-mt"><?= htmlspecialchars($email_error) ?></div>
            <?php endif; ?>
            <?php if ($email_success): ?>
                <div class="alert alert-success alert-mt"><?= htmlspecialchars($email_success) ?></div>
            <?php endif; ?>
        </div>

        <!-- Password Form (hidden by default) -->
        <div id="password-section" class="toggle-section">
            <form method="POST">
                <div class="form-group">
                    <label>Current Password</label>
                    <input type="password" name="old_password"
                           placeholder="Enter current password" required>
                </div>
                <div class="form-group">
                    <label>New Password</label>
                    <input type="password" name="new_password"
                           placeholder="Min 8 chars, upper, lower, number" required>
                </div>
                <div class="form-group">
                    <label>Confirm New Password</label>
                    <input type="password" name="confirm_password"
                           placeholder="Repeat new password" required>
                </div>
                <div class="form-actions">
                    <button type="submit" name="change_password" class="btn btn-primary btn-flex">
                        Update Password
                    </button>
                    <button type="button" class="btn btn-outline"
                            onclick="toggleSection('password-section')">
                        Cancel
                    </button>
                </div>
            </form>
            <?php if ($pw_error): ?>
                <div class="alert alert-error alert-mt"><?= htmlspecialchars($pw_error) ?></div>
            <?php endif; ?>
            <?php if ($pw_success): ?>
                <div class="alert alert-success alert-mt"><?= htmlspecialchars($pw_success) ?></div>
            <?php endif; ?>
        </div>

    </div>

</div><!-- end .dashboard -->


<script>
    // ---- Toggle section function ----
    function toggleSection(id) {
        var el = document.getElementById(id);
        if (el) {
            el.style.display = (el.style.display === 'none' || el.style.display === '')
                ? 'block'
                : 'none';
        }
    }

    // ---- Auto logout after 30 minutes ----
    const loginTime = <?= $_SESSION['loginTime'] ?> * 1000;
    const limit     = 30 * 60 * 1000;
    const remaining = limit - (Date.now() - loginTime);

    if (remaining <= 0) {
        window.location.href = 'logout.php?msg=expired';
    } else {
        setTimeout(() => {
            alert('Your session has expired. You will be logged out.');
            window.location.href = 'logout.php?msg=expired';
        }, remaining);
    }
</script>

</body>
</html>
