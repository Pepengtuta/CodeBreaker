<?php
// ============================================
// admin.php — Admin Dashboard
//
// Tabbed layout: Manage Users | Login Logs |
//                Action Logs  | Add User
//
// Access: admin role only.
// Root admin (id=1) has extra delete privileges.
// ============================================

session_start();
require_once 'db.php';

header('Cache-Control: no-store, no-cache, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');

// ---- Session Guard ----
if (!isset($_SESSION['username'])) {
    header("Location: login.php");
    exit;
}

// ---- Session Expiration (30 minutes) ----
$session_limit = 30 * 60;
if (isset($_SESSION['loginTime']) && (time() - $_SESSION['loginTime']) > $session_limit) {
    session_destroy();
    header("Location: login.php?msg=expired");
    exit;
}

// ---- Role Check — ADMINS ONLY ----
if ($_SESSION['role'] !== 'admin') {
    log_action($conn, $_SESSION['username'], 'attempted unauthorized admin access');
    die('<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Access Denied</title>
         <link rel="stylesheet" href="style.css"></head><body>
         <div class="access-denied">
             <h2>Access Denied</h2>
             <p>You do not have permission to view this page.</p>
             <a href="dashboard.php">Go to your dashboard</a>
         </div></body></html>');
}

// ---- Get current admin ID to determine if root ----
// Root admin (id=1) has extra privileges: can delete admin accounts
$current_admin_id = (int)($_SESSION['user_id'] ?? 0);
if ($current_admin_id === 0) {
    // Fallback: look up by username if user_id not in session yet
    $stmt = $conn->prepare("SELECT id FROM users WHERE username = ? LIMIT 1");
    $stmt->bind_param("s", $_SESSION['username']);
    $stmt->execute();
    $row = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    $current_admin_id = (int)($row['id'] ?? 0);
}
$is_root_admin = ($current_admin_id === 1);

$message      = '';
$message_type = '';
$active_tab   = $_GET['tab'] ?? 'users'; // default tab

// ============================================
// UNLOCK ACCOUNT (POST)
// ============================================
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'unlock_user') {
    $unlock_id = (int)($_POST['unlock_id'] ?? 0);
    if ($unlock_id < 1 || !cb_unlock_user_account($conn, $unlock_id)) {
        $message      = 'Could not unlock account.';
        $message_type = 'error';
    } else {
        log_action($conn, $_SESSION['username'], "unlocked account #$unlock_id");
        header('Location: admin.php?tab=users&msg=unlocked');
        exit;
    }
}

// ============================================
// ADD USER
// ============================================
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'add_user') {

    $new_username = trim($_POST['new_username'] ?? '');
    $new_password = $_POST['new_password'] ?? '';
    $new_role     = $_POST['new_role'] ?? 'user';
    $new_email    = trim($_POST['new_email'] ?? '');
    $sq_question  = trim($_POST['sq_question'] ?? '');
    $sq_answer    = trim($_POST['sq_answer'] ?? '');

    if (empty($new_username) || empty($new_password) || empty($sq_question) || empty($sq_answer)) {
        $message = "All fields are required.";
        $message_type = 'error';
        $active_tab = 'users';

    } elseif (!empty($new_email) && !filter_var($new_email, FILTER_VALIDATE_EMAIL)) {
        $message = "Invalid email address.";
        $message_type = 'error';
        $active_tab = 'users';

    } elseif (!in_array($new_role, ['admin', 'user'])) {
        $message = "Invalid role.";
        $message_type = 'error';
        $active_tab = 'users';

    } elseif (strlen($new_password) < 8 ||
              !preg_match('/[A-Z]/', $new_password) ||
              !preg_match('/[a-z]/', $new_password) ||
              !preg_match('/[0-9]/', $new_password)) {
        $message = "Password must be at least 8 characters with uppercase, lowercase, and a number.";
        $message_type = 'error';
        $active_tab = 'users';

    } else {
        $stmt = $conn->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->bind_param("s", $new_username);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            $message = "Username already exists.";
            $message_type = 'error';
            $stmt->close();
            $active_tab = 'users';

        } else {
            $stmt->close();
            $pw_hash   = password_hash($new_password, PASSWORD_BCRYPT);
            $email_val = !empty($new_email) ? $new_email : null;

            $stmt = $conn->prepare(
                "INSERT INTO users (username, password_hash, role, email) VALUES (?, ?, ?, ?)"
            );
            $stmt->bind_param("ssss", $new_username, $pw_hash, $new_role, $email_val);
            $stmt->execute();
            $new_user_id = $conn->insert_id;
            $stmt->close();

            $ans_hash = password_hash(strtolower(trim($sq_answer)), PASSWORD_BCRYPT);
            $stmt = $conn->prepare(
                "INSERT INTO security_questions (user_id, question, answer_hash) VALUES (?, ?, ?)"
            );
            $stmt->bind_param("iss", $new_user_id, $sq_question, $ans_hash);
            $stmt->execute();
            $stmt->close();

            log_action($conn, $_SESSION['username'], "added user: $new_username ($new_role)");
            header('Location: admin.php?tab=users&msg=added');
            exit;
        }
    }
}

// ============================================
// UPDATE USER
// ============================================
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'update_user') {
    $edit_id     = (int)$_POST['edit_id'];
    $username    = trim($_POST['username'] ?? '');
    $role        = $_POST['role'] ?? 'user';
    $password    = $_POST['password'] ?? '';
    $edit_email  = trim($_POST['edit_email'] ?? '');
    $sq_question = trim($_POST['sq_question'] ?? '');
    $sq_answer   = trim($_POST['sq_answer'] ?? '');

    if ($edit_id === 1) {
        $message = "Cannot edit root admin.";
        $message_type = 'error';

    } elseif (empty($username) || empty($sq_question) || empty($sq_answer)) {
        $message = "Required fields cannot be empty.";
        $message_type = 'error';

    } elseif (!empty($edit_email) && !filter_var($edit_email, FILTER_VALIDATE_EMAIL)) {
        $message = "Invalid email address.";
        $message_type = 'error';

    } elseif (!in_array($role, ['admin', 'user'])) {
        $message = "Invalid role.";
        $message_type = 'error';

    } elseif (!empty($password) && (
        strlen($password) < 8 ||
        !preg_match('/[A-Z]/', $password) ||
        !preg_match('/[a-z]/', $password) ||
        !preg_match('/[0-9]/', $password)
    )) {
        $message = "Password must be 8+ chars with upper, lower, number.";
        $message_type = 'error';

    } else {
        $stmt = $conn->prepare("SELECT id FROM users WHERE username = ? AND id != ?");
        $stmt->bind_param("si", $username, $edit_id);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            $message = "Username already taken.";
            $message_type = 'error';
            $stmt->close();

        } else {
            $stmt->close();
            $conn->begin_transaction();

            try {
                $email_upd = !empty($edit_email) ? $edit_email : null;

                if (!empty($password)) {
                    $pw_hash = password_hash($password, PASSWORD_BCRYPT);
                    $stmt = $conn->prepare(
                        "UPDATE users SET username=?, role=?, password_hash=?, email=? WHERE id=?"
                    );
                    $stmt->bind_param("ssssi", $username, $role, $pw_hash, $email_upd, $edit_id);
                } else {
                    $stmt = $conn->prepare(
                        "UPDATE users SET username=?, role=?, email=? WHERE id=?"
                    );
                    $stmt->bind_param("sssi", $username, $role, $email_upd, $edit_id);
                }
                $stmt->execute();
                $stmt->close();

                $ans_hash = password_hash(strtolower(trim($sq_answer)), PASSWORD_BCRYPT);

                $stmt = $conn->prepare("DELETE FROM security_questions WHERE user_id=?");
                $stmt->bind_param("i", $edit_id);
                $stmt->execute();
                $stmt->close();

                $stmt = $conn->prepare(
                    "INSERT INTO security_questions (user_id, question, answer_hash) VALUES (?,?,?)"
                );
                $stmt->bind_param("iss", $edit_id, $sq_question, $ans_hash);
                $stmt->execute();
                $stmt->close();

                $conn->commit();
                log_action($conn, $_SESSION['username'], "updated user #$edit_id ($username)");
                header('Location: admin.php?tab=users&msg=updated');
                exit;

            } catch (Exception $e) {
                $conn->rollback();
                $message = "Update failed. Please try again.";
                $message_type = 'error';
            }
        }
    }
}

// ============================================
// DELETE USER
// Only root admin (id=1) can delete admin accounts.
// Regular admins can only delete user-role accounts.
// ============================================
if (isset($_GET['delete_id'])) {
    $del_id = (int)$_GET['delete_id'];

    if ($del_id === 1) {
        $message = "Cannot delete the root admin account.";
        $message_type = 'error';

    } elseif ($del_id < 1) {
        $message = "Invalid user.";
        $message_type = 'error';

    } else {
        // Check the target user's role
        $stmt = $conn->prepare("SELECT username, role FROM users WHERE id = ?");
        $stmt->bind_param("i", $del_id);
        $stmt->execute();
        $del_row = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        if (!$del_row) {
            $message = "User not found.";
            $message_type = 'error';

        } elseif ($del_row['role'] === 'admin' && !$is_root_admin) {
            // Non-root admins cannot delete other admin accounts
            log_action($conn, $_SESSION['username'], "attempted to delete admin account #{$del_id}");
            $message = "Only the root admin can delete admin accounts.";
            $message_type = 'error';

        } else {
            $conn->begin_transaction();
            try {
                $stmt = $conn->prepare("DELETE FROM security_questions WHERE user_id = ?");
                $stmt->bind_param("i", $del_id);
                if (!$stmt->execute()) throw new Exception($stmt->error);
                $stmt->close();

                $stmt = $conn->prepare("DELETE FROM users WHERE id = ?");
                $stmt->bind_param("i", $del_id);
                if (!$stmt->execute()) throw new Exception($stmt->error);
                if ($stmt->affected_rows < 1) throw new Exception('Row not removed.');
                $stmt->close();

                $conn->commit();
                log_action($conn, $_SESSION['username'], "deleted user: {$del_row['username']}");
                header('Location: admin.php?tab=users&msg=deleted');
                exit;

            } catch (Exception $e) {
                $conn->rollback();
                $message = "Could not delete user.";
                $message_type = 'error';
            }
        }
    }
}

// ============================================
// UNLOCK ACCOUNT (GET fallback)
// ============================================
if (isset($_GET['unlock_id'])) {
    $unlock_id = (int)$_GET['unlock_id'];
    if ($unlock_id < 1 || !cb_unlock_user_account($conn, $unlock_id)) {
        $message = 'Could not unlock account.';
        $message_type = 'error';
    } else {
        log_action($conn, $_SESSION['username'], "unlocked account #$unlock_id");
        header('Location: admin.php?tab=users&msg=unlocked');
        exit;
    }
}

// ============================================
// CLEAR LOGIN LOGS
// ============================================
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'clear_logs') {
    $conn->query("TRUNCATE TABLE login_logs");
    log_action($conn, $_SESSION['username'], 'cleared all login logs');
    header('Location: admin.php?tab=login_logs&msg=logs_cleared');
    exit;
}

// ============================================
// FLASH MESSAGES from redirects
// ============================================
$msg_map = [
    'unlocked'     => ['Account unlocked successfully.', 'success'],
    'added'        => ['User created successfully.',     'success'],
    'updated'      => ['User updated successfully.',     'success'],
    'deleted'      => ['User deleted.',                  'success'],
    'logs_cleared' => ['Login logs cleared.',            'success'],
];
if (isset($_GET['msg']) && isset($msg_map[$_GET['msg']])) {
    [$message, $message_type] = $msg_map[$_GET['msg']];
}

// ============================================
// LOAD EDIT FORM DATA
// ============================================
$edit_user = null;
$edit_sq   = null;
if (isset($_GET['edit_id'])) {
    $edit_id = (int)$_GET['edit_id'];
    $active_tab = 'users';
    if ($edit_id != 1) {
        $stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->bind_param("i", $edit_id);
        $stmt->execute();
        $edit_user = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        if ($edit_user) {
            $stmt = $conn->prepare(
                "SELECT * FROM security_questions WHERE user_id = ? LIMIT 1"
            );
            $stmt->bind_param("i", $edit_id);
            $stmt->execute();
            $edit_sq = $stmt->get_result()->fetch_assoc();
            $stmt->close();
        }
    }
}

// ============================================
// LOAD PAGE DATA
// ============================================
$users_result = $conn->query(
    'SELECT * FROM users WHERE id != 1 ORDER BY created_at DESC'
);
$logs_result = $conn->query(
    "SELECT * FROM login_logs ORDER BY timestamp DESC LIMIT 50"
);
$action_logs_result = $conn->query(
    "SELECT * FROM action_logs ORDER BY timestamp DESC LIMIT 50"
);

// ---- Stat counts ----
$total_users  = $conn->query('SELECT COUNT(*) AS c FROM users WHERE id != 1')->fetch_assoc()['c'];
$locked_count = 0;
$lock_q = $conn->query('SELECT lock_until FROM users WHERE lock_until IS NOT NULL');
if ($lock_q) {
    while ($lr = $lock_q->fetch_assoc()) {
        if (cb_user_login_cooldown_active($lr['lock_until'] ?? null)) $locked_count++;
    }
}
$failed_today  = $conn->query(
    "SELECT COUNT(*) AS c FROM login_logs WHERE status='FAILED' AND DATE(timestamp)=CURDATE()"
)->fetch_assoc()['c'];
$success_today = $conn->query(
    "SELECT COUNT(*) AS c FROM login_logs WHERE status='SUCCESS' AND DATE(timestamp)=CURDATE()"
)->fetch_assoc()['c'];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
    <meta http-equiv="Pragma" content="no-cache">
    <meta http-equiv="Expires" content="0">
    <title>Admin - Code Breaker</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>

<!-- Navbar -->
<div class="navbar">
    <a href="index.php" class="logo">[ CODE BREAKER ]</a>
    <nav>
        <a href="admin.php" class="active">Admin Panel</a>
        <a href="logout.php">Logout</a>
    </nav>
</div>

<div class="dashboard">

    <!-- Header -->
    <div class="dashboard-header">
        <div>
            <h1>Admin Dashboard</h1>
            <p>Logged in as <strong><?= htmlspecialchars($_SESSION['username']) ?></strong>
               &nbsp;<span class="badge badge-admin">ADMIN</span>
               <?php if ($is_root_admin): ?>
                   &nbsp;<span class="badge badge-root">ROOT</span>
               <?php endif; ?>
            </p>
        </div>
        <a href="logout.php" class="btn btn-outline btn-sm">Logout</a>
    </div>

    <!-- Flash message -->
    <?php if ($message): ?>
        <div class="alert alert-<?= $message_type ?>">
            <?= htmlspecialchars($message) ?>
        </div>
    <?php endif; ?>

    <!-- ---- Stat Cards ---- -->
    <div class="stat-grid">
        <div class="stat-card">
            <div class="stat-num"><?= $total_users ?></div>
            <div class="stat-label">Total Users</div>
        </div>
        <div class="stat-card">
            <div class="stat-num stat-num-warning"><?= $locked_count ?></div>
            <div class="stat-label">Locked Accounts</div>
        </div>
        <div class="stat-card">
            <div class="stat-num stat-num-danger"><?= $failed_today ?></div>
            <div class="stat-label">Failed Logins Today</div>
        </div>
        <div class="stat-card">
            <div class="stat-num stat-num-success"><?= $success_today ?></div>
            <div class="stat-label">Successful Logins Today</div>
        </div>
    </div>

    <!-- ---- Tab Bar ---- -->
    <div class="tab-bar">
        <button class="tab-btn <?= $active_tab === 'users' ? 'active' : '' ?>"
                data-tab="users">
            Manage Users
        </button>
        <button class="tab-btn <?= $active_tab === 'login_logs' ? 'active' : '' ?>"
                data-tab="login_logs">
            Login Logs
        </button>
        <button class="tab-btn <?= $active_tab === 'action_logs' ? 'active' : '' ?>"
                data-tab="action_logs">
            Action Logs
        </button>
        <button class="tab-btn <?= $active_tab === 'add_user' ? 'active' : '' ?>"
                data-tab="add_user">
            + Add User
        </button>
    </div>

    <!-- ============================================
         TAB: MANAGE USERS
         ============================================ -->
    <div id="tab-users" class="tab-pane <?= $active_tab === 'users' ? 'active' : '' ?>">

        <!-- Edit User Form — slides in when edit button is clicked -->
        <?php if ($edit_user): ?>
        <div class="card card-edit">
            <p class="section-title">
                Editing: <?= htmlspecialchars($edit_user['username']) ?>
                <a href="admin.php?tab=users" class="cancel-link">&times; Cancel</a>
            </p>

            <form method="POST" action="admin.php">
                <input type="hidden" name="action" value="update_user">
                <input type="hidden" name="edit_id" value="<?= $edit_user['id'] ?>">

                <div class="grid-2">
                    <div class="form-group">
                        <label>Username</label>
                        <input type="text" name="username"
                               value="<?= htmlspecialchars($edit_user['username']) ?>"
                               required autocomplete="off">
                    </div>
                    <div class="form-group">
                        <label>New Password <span class="label-note">(blank = keep)</span></label>
                        <input type="password" name="password" placeholder="Leave blank to keep current">
                    </div>
                    <div class="form-group">
                        <label>Role</label>
                        <select name="role">
                            <option value="user"  <?= $edit_user['role'] === 'user'  ? 'selected' : '' ?>>User</option>
                            <option value="admin" <?= $edit_user['role'] === 'admin' ? 'selected' : '' ?>>Admin</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Email <span class="label-note">(optional)</span></label>
                        <input type="email" name="edit_email"
                               value="<?= htmlspecialchars($edit_user['email'] ?? '') ?>"
                               placeholder="user@email.com">
                    </div>
                    <div class="form-group">
                        <label>Security Question</label>
                        <input type="text" name="sq_question"
                               value="<?= htmlspecialchars($edit_sq['question'] ?? '') ?>" required>
                    </div>
                    <div class="form-group">
                        <label>New Security Answer</label>
                        <input type="text" name="sq_answer"
                               placeholder="Enter new answer" required autocomplete="off">
                    </div>
                </div>

                <div class="form-actions">
                    <button type="submit" class="btn btn-primary btn-flex">Save Changes</button>
                    <a href="admin.php?tab=users" class="btn btn-outline">Cancel</a>
                </div>
            </form>
        </div>
        <?php endif; ?>

        <!-- Users Table -->
        <div class="card card-full">
            <p class="section-title">All Users</p>

            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Username</th>
                            <th>Email</th>
                            <th>Role</th>
                            <th>Failed Attempts</th>
                            <th>Status</th>
                            <th>Created</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                    <?php while ($u = $users_result->fetch_assoc()): ?>
                        <?php
                        $is_locked       = cb_user_login_cooldown_active($u['lock_until'] ?? null);
                        $needs_unlock    = $is_locked || (int)($u['failed_attempts'] ?? 0) >= 3;
                        $target_is_admin = ($u['role'] === 'admin');
                        // Delete allowed if: target is user-role, OR current user is root admin
                        $can_delete      = (!$target_is_admin || $is_root_admin);
                        ?>
                        <tr>
                            <td><?= $u['id'] ?></td>
                            <td><?= htmlspecialchars($u['username']) ?></td>
                            <td>
                                <?php if (!empty($u['email'])): ?>
                                    <?= htmlspecialchars($u['email']) ?>
                                <?php else: ?>
                                    <span class="text-muted">—</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <span class="badge badge-<?= $u['role'] ?>">
                                    <?= strtoupper($u['role']) ?>
                                </span>
                            </td>
                            <td><?= $u['failed_attempts'] ?></td>
                            <td>
                                <span class="badge <?= $is_locked ? 'badge-locked' : 'badge-success' ?>">
                                    <?= $is_locked ? 'Locked' : 'Active' ?>
                                </span>
                            </td>
                            <td><?= $u['created_at'] ?></td>
                            <td class="td-actions">
                                <div class="action-row">
                                    <?php if ($needs_unlock): ?>
                                        <form method="post" action="admin.php" class="form-inline-unlock">
                                            <input type="hidden" name="action" value="unlock_user">
                                            <input type="hidden" name="unlock_id" value="<?= (int)$u['id'] ?>">
                                            <button type="submit" class="btn btn-warning btn-sm">Unlock</button>
                                        </form>
                                    <?php endif; ?>

                                    <a href="admin.php?edit_id=<?= $u['id'] ?>&tab=users"
                                       class="btn btn-outline btn-sm">Edit</a>

                                    <?php if ($can_delete): ?>
                                        <?php
                                        $conf = json_encode(
                                            'Delete ' . $u['username'] . '? This cannot be undone.',
                                            JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT
                                        );
                                        ?>
                                        <a href="admin.php?delete_id=<?= (int)$u['id'] ?>&tab=users"
                                           class="btn btn-danger btn-sm"
                                           onclick="return confirm(<?= $conf ?>)">
                                            Delete
                                        </a>
                                    <?php endif; ?>
                                </div>
                            </td>
                        </tr>
                    <?php endwhile; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- ============================================
         TAB: LOGIN LOGS
         ============================================ -->
    <div id="tab-login_logs" class="tab-pane <?= $active_tab === 'login_logs' ? 'active' : '' ?>">
        <div class="card card-full">
            <div class="tab-header">
                <p class="section-title">Recent Login Logs (Last 50)</p>
                <form method="POST" action="admin.php"
                      onsubmit="return confirm('Clear ALL login logs? This cannot be undone.');">
                    <input type="hidden" name="action" value="clear_logs">
                    <button type="submit" class="btn btn-danger btn-sm">&times; Clear All Logs</button>
                </form>
            </div>

            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Username</th>
                            <th>Timestamp</th>
                            <th>Status</th>
                            <th>Reason</th>
                            <th>IP Address</th>
                        </tr>
                    </thead>
                    <tbody>
                    <?php while ($log = $logs_result->fetch_assoc()): ?>
                        <tr>
                            <td><?= $log['id'] ?></td>
                            <td><?= htmlspecialchars($log['username']) ?></td>
                            <td><?= $log['timestamp'] ?></td>
                            <td>
                                <span class="badge badge-<?= strtolower($log['status']) ?>">
                                    <?= $log['status'] ?>
                                </span>
                            </td>
                            <td><?= htmlspecialchars($log['reason']) ?></td>
                            <td><?= htmlspecialchars($log['ip_address'] ?? '—') ?></td>
                        </tr>
                    <?php endwhile; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- ============================================
         TAB: ACTION LOGS
         ============================================ -->
    <div id="tab-action_logs" class="tab-pane <?= $active_tab === 'action_logs' ? 'active' : '' ?>">
        <div class="card card-full">
            <p class="section-title">Action Logs (Last 50)</p>
            <p class="tab-description">
                Records all admin actions — user creation, deletion, unlocks, and logout events.
            </p>

            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Username</th>
                            <th>Action</th>
                            <th>Timestamp</th>
                        </tr>
                    </thead>
                    <tbody>
                    <?php
                    $has_action_logs = false;
                    while ($al = $action_logs_result->fetch_assoc()):
                        $has_action_logs = true;
                    ?>
                        <tr>
                            <td><?= $al['id'] ?></td>
                            <td><?= htmlspecialchars($al['username']) ?></td>
                            <td><?= htmlspecialchars($al['action']) ?></td>
                            <td><?= $al['timestamp'] ?></td>
                        </tr>
                    <?php endwhile; ?>
                    <?php if (!$has_action_logs): ?>
                        <tr>
                            <td colspan="4" class="td-empty">No action logs yet.</td>
                        </tr>
                    <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- ============================================
         TAB: ADD USER
         ============================================ -->
    <div id="tab-add_user" class="tab-pane <?= $active_tab === 'add_user' ? 'active' : '' ?>">
        <div class="card card-full">
            <p class="section-title">Add New User</p>

            <form method="POST" action="admin.php">
                <input type="hidden" name="action" value="add_user">

                <div class="grid-2">
                    <div class="form-group">
                        <label>Username</label>
                        <input type="text" name="new_username"
                               placeholder="e.g. jdelacruz" required autocomplete="off">
                    </div>
                    <div class="form-group">
                        <label>Password</label>
                        <input type="password" name="new_password"
                               placeholder="Min 8 chars, upper+lower+number" required>
                    </div>
                    <div class="form-group">
                        <label>Role</label>
                        <select name="new_role">
                            <option value="user">User</option>
                            <option value="admin">Admin</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Email <span class="label-note">(optional)</span></label>
                        <input type="email" name="new_email" placeholder="user@email.com">
                    </div>
                    <div class="form-group">
                        <label>Security Question</label>
                        <input type="text" name="sq_question"
                               placeholder="e.g. What is your pet's name?" required>
                    </div>
                    <div class="form-group">
                        <label>Security Answer</label>
                        <input type="text" name="sq_answer"
                               placeholder="Answer (case-insensitive)" required autocomplete="off">
                    </div>
                </div>

                <div class="form-actions">
                    <button type="submit" class="btn btn-primary btn-flex">Create User</button>
                    <a href="admin.php?tab=users" class="btn btn-outline">Cancel</a>
                </div>
            </form>
        </div>
    </div>

</div><!-- end .dashboard -->


<script>
    // ---- Tab switching ----
    var activeTab = '<?= $active_tab ?>';

    document.querySelectorAll('.tab-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
            switchTab(this.dataset.tab);
        });
    });

    function switchTab(name) {
        // Hide all panes
        document.querySelectorAll('.tab-pane').forEach(function(p) {
            p.classList.remove('active');
        });
        // Deactivate all buttons
        document.querySelectorAll('.tab-btn').forEach(function(b) {
            b.classList.remove('active');
        });
        // Show selected pane
        var pane = document.getElementById('tab-' + name);
        if (pane) pane.classList.add('active');
        // Activate matching button
        var btn = document.querySelector('[data-tab="' + name + '"]');
        if (btn) btn.classList.add('active');
        activeTab = name;
    }

    // ---- Auto logout ----
    const loginTime = <?= $_SESSION['loginTime'] ?> * 1000;
    const limit     = 30 * 60 * 1000;
    const remaining = limit - (Date.now() - loginTime);

    if (remaining <= 0) {
        window.location.href = 'logout.php?msg=expired';
    } else {
        setTimeout(function() {
            alert('Your admin session has expired.');
            window.location.href = 'logout.php?msg=expired';
        }, remaining);
    }
</script>

</body>
</html>
