<?php
session_start();
if (!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true) {
    if (isset($_COOKIE["user"])) {
        // Restore session from cookie
        $_SESSION["loggedin"] = true;
        $_SESSION["username"] = $_COOKIE["user"];
        // Optionally, query the database to get more user details if needed
    } else {
        header("location: login.html");
        exit;
    }
}
setcookie("user", $_SESSION["username"], time() + (86400 * 30), "/"); // Renew for another 30 days
?>

<!DOCTYPE html>
<html>
<head>
    <title>UCommerce</title>
</head>
<body>
    <h1>Welcome, <?php echo $_SESSION["username"]; ?></h1>
    <a href="logout.php">Logout</a>
</body>
</html>