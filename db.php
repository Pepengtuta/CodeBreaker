<?php
// ============================================
// db.php — Database Connection & Shared Functions
//
// Include this on every page that needs the DB.
// Also defines all helper functions used
// across the app (lockout checks, logging, etc.)
// ============================================

// --- Change these to match your XAMPP setup ---
$db_host = "localhost";
$db_user = "root";
$db_pass = "";
$db_name = "codebreaker_db";

// Connect
$conn = new mysqli($db_host, $db_user, $db_pass, $db_name);

if ($conn->connect_error) {
    die("Connection failed. Please contact the administrator.");
}

$conn->set_charset("utf8");

// Sync PHP and MySQL timezone so lockout timers don't drift
$timezone = date('P');
if (preg_match('/^[+-](?:0\d|1[0-4]):[0-5]\d$/', $timezone)) {
    @$conn->query("SET SESSION time_zone = '" . $conn->real_escape_string($timezone) . "'");
}

// Add lockout_tier column if it doesn't exist yet (older databases)
$col_check = @$conn->query("SHOW COLUMNS FROM users LIKE 'lockout_tier'");
if ($col_check && $col_check->num_rows === 0) {
    @$conn->query("ALTER TABLE users ADD COLUMN lockout_tier INT NOT NULL DEFAULT 0 AFTER lock_until");
}
if ($col_check) {
    $col_check->close();
}

// ============================================
// FUNCTIONS
// ============================================

// Convert lock_until to Unix timestamp — returns null if not locked
function cb_lock_until_timestamp($lock_until) {
    if ($lock_until === null || $lock_until === '' || $lock_until === '0000-00-00 00:00:00') {
        return null;
    }
    $t = strtotime((string)$lock_until);
    return $t === false ? null : $t;
}

// Returns true if the account lockout window is still active
function cb_user_login_cooldown_active($lock_until) {
    $ts = cb_lock_until_timestamp($lock_until);
    return $ts !== null && $ts > time();
}

// Admin unlock — clears all lockout fields for a user
function cb_unlock_user_account(mysqli $conn, int $userId) {
    if ($userId < 1) {
        return false;
    }

    $chk = $conn->query('SELECT id FROM users WHERE id = ' . (int)$userId . ' LIMIT 1');
    if (!$chk || $chk->num_rows < 1) {
        return false;
    }

    $stmt = $conn->prepare('UPDATE users SET failed_attempts = 0, lock_until = NULL, lockout_tier = 0 WHERE id = ?');
    $stmt->bind_param('i', $userId);

    if (!$stmt->execute()) {
        // Fallback for older databases without lockout_tier column
        $stmt->close();
        $stmt = $conn->prepare('UPDATE users SET failed_attempts = 0, lock_until = NULL WHERE id = ?');
        $stmt->bind_param('i', $userId);
        $stmt->execute();
        $stmt->close();
    } else {
        $stmt->close();
    }

    return true;
}

// Log every login attempt to login_logs table
function log_login($conn, $username, $status, $reason) {
    $ip   = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $stmt = $conn->prepare("INSERT INTO login_logs (username, status, reason, ip_address) VALUES (?, ?, ?, ?)");
    $stmt->bind_param("ssss", $username, $status, $reason, $ip);
    $stmt->execute();
    $stmt->close();
}

// Log admin actions to action_logs table
function log_action($conn, $username, $action) {
    $stmt = $conn->prepare("INSERT INTO action_logs (username, action) VALUES (?, ?)");
    $stmt->bind_param("ss", $username, $action);
    $stmt->execute();
    $stmt->close();
}
