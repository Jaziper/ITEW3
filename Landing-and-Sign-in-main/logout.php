<?php
session_start();
$_SESSION = array();
session_destroy();

if (isset($_COOKIE["user"])) {
    setcookie("user", "", time() - 3600, "/"); // Expire the cookie
}

// Redirect to index.html
header("location: index.html");
exit;
?>