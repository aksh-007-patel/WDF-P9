<?php
// Practical 9: DB connection using MySQLi
// XAMPP defaults: host=localhost, user=root, password="" (empty)

define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', '');
define('DB_NAME', 'practical9_db');

mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

try {
    $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    $conn->set_charset('utf8mb4');
} catch (mysqli_sql_exception $e) {
    die('Database connection failed. Make sure MySQL is running in XAMPP '
        . 'and you have imported database.sql. Error: '
        . htmlspecialchars($e->getMessage()));
}
