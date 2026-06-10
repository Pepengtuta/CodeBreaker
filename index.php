<?php
// ============================================
// index.php — Home / Landing Page
//
// First page users see. Shows an overview of
// the security features and links to login
// (or to the dashboard if already logged in).
// ============================================

session_start();

// Prevent browser from caching this page
header('Cache-Control: no-store, no-cache, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
    <meta http-equiv="Pragma" content="no-cache">
    <meta http-equiv="Expires" content="0">
    <title>Code Breaker Security System</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>

<!-- Navbar -->
<div class="navbar">
    <a href="index.php" class="logo">[ CODE BREAKER ]</a>
    <nav>
        <?php if (isset($_SESSION['username'])): ?>
            <!-- Logged in — show dashboard link -->
            <a href="<?= $_SESSION['role'] === 'admin' ? 'admin.php' : 'dashboard.php' ?>">
                Dashboard
            </a>
            <a href="logout.php">Logout</a>
        <?php else: ?>
            <!-- Not logged in — go to CAPTCHA first -->
            <a href="captcha_verify.php">Login</a>
        <?php endif; ?>
    </nav>
</div>

<!-- Main Content -->
<div class="page-wrapper">
    <div class="card card-home">

        <div class="card-header">
            <div class="icon"></div>
            <h1>CODE BREAKER</h1>
            <p>Advanced Security System</p>
        </div>

        <!-- Security feature list -->
        <div class="features-list">
            <p class="features-intro">
                This system demonstrates real-world cybersecurity practices:
            </p>

            <div class="features-items">
                <?php
                $features = [
                    'Hashed Password Authentication',
                    'Two-Step Security Question Verification',
                    'Account Lockout After 3 Failed Attempts',
                    'Role-Based Access Control (Admin / User)',
                    'Full Login Activity Logging',
                    'SQL Injection Protection',
                    'Automatic Session Expiration (30 min)',
                ];
                foreach ($features as $text):
                ?>
                    <div class="feature-item">
                        <span><?= $text ?></span>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- CTA button — dashboard if logged in, login otherwise -->
        <?php if (isset($_SESSION['username'])): ?>
            <a href="<?= $_SESSION['role'] === 'admin' ? 'admin.php' : 'dashboard.php' ?>"
               class="btn btn-primary">
                Go to Dashboard &rarr;
            </a>
        <?php else: ?>
            <a href="captcha_verify.php" class="btn btn-primary">
                Proceed to Login &rarr;
            </a>
        <?php endif; ?>

    </div>
</div>

</body>
</html>
