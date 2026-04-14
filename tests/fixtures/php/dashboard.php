<?php
// Fixture: a guarded PHP page that includes auth -> PROTECTED.
require_once 'auth.php';
if (empty($_SESSION['admin_logged_in'])) {
    header('Location: login.php');
    exit;
}
echo "dashboard";
