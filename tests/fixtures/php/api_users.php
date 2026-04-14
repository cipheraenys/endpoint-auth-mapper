<?php
// Fixture: a classic PHP endpoint with NO auth include -> UNKNOWN/EXPOSED.
require_once 'config.php';

$action = $_GET['action'] ?? '';
echo json_encode(['action' => $action]);
