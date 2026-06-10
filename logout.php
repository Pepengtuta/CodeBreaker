<?php
// ============================================
// logout.php — Logout
//
// Clears the session completely and redirects
// to the home page. Passes the reason (logout
// or expired) so index.php can show a message.
// ============================================

session_start();

// Prevent the browser from caching this page
header('Cache-Control: no-store, no-cache, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');

// Log the logout action if we know who is leaving
if (isset($_SESSION['username'])) {
    require_once 'db.php';
    log_action($conn, $_SESSION['username'], 'logged out');
}

// Clear all session variables
$_SESSION = [];

// Delete the session cookie from the browser
if (isset($_COOKIE[session_name()])) {
    setcookie(session_name(), '', time() - 3600, '/');
}

// Destroy the session on the server
session_destroy();

// Redirect home — pass reason so index.php can display a message if needed
$reason = $_GET['msg'] ?? 'logout';
header("Cache-Control: no-store, no-cache, must-revalidate");
header("Pragma: no-cache");
header("Expires: 0");
header("Location: index.php?msg=$reason");
exit;
