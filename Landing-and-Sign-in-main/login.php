<?php
require 'db_config.php';
session_start();
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email = trim($_POST["email"]);
    $password = trim($_POST["password"]);

    $sql = "SELECT id, email, username, password FROM users WHERE email = ?";
    if ($stmt = $conn->prepare($sql)) {
        $stmt->bind_param("s", $email);
        if ($stmt->execute()) {
            $stmt->store_result();
            if ($stmt->num_rows == 1) {
                $stmt->bind_result($id, $email, $username, $hashed_password);
                if ($stmt->fetch()) {
                    if (password_verify($password, $hashed_password)) {
                        $_SESSION["loggedin"] = true;
                        $_SESSION["id"] = $id;
                        $_SESSION["username"] = $username;

                        setcookie("user", $username, time() + (86400 * 30), "/"); // 30 days

                        header("location: dashboard.php");
                    } else {
                        echo "Invalid email or password. <a href='login.html'>Go back</a>";
                    }
                }
            } else {
                echo "Invalid email or password. <a href='index.html'>Go back</a>";
            }
        } else {
            echo "Error: " . $stmt->error;
        }
        $stmt->close();
    }
    $conn->close();
}
?>