<?php 
require 'db_config.php';
session_start();

// Enable detailed error reporting
ini_set('display_errors', 1);
error_reporting(E_ALL);

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email = trim($_POST["email"]);
    $password = trim($_POST["password"]);
    $remember = isset($_POST['remember']);

    // Check if email and password are empty
    if (empty($email) || empty($password)) {
        echo "Email and password cannot be empty.";
        exit;
    }

    // SQL query to fetch user details
    $sql = "SELECT id, username, password FROM users WHERE email = ?";
    // Prepare the SQL statement
    if ($stmt = $conn->prepare($sql)) {
        // Bind the email to the prepared statement
        $stmt->bind_param("s", $email);

        // Execute the statement
        if ($stmt->execute()) {
            $stmt->store_result();

            // Check if a user was found
            if ($stmt->num_rows == 1) {
                // Bind the results to variables
                $stmt->bind_result($id, $username, $hashed_password);

                // Fetch the result
                if ($stmt->fetch()) {
                    // Verify the password
                    if (password_verify($password, $hashed_password)) {
                        // Set session variables for the logged-in user
                        $_SESSION["loggedin"] = true;
                        $_SESSION["id"] = $id;
                        $_SESSION["username"] = $username;

                        // Check if 'Remember Me' was selected and set a cookie
                         // If "Remember Me" is checked, store in cookies 
                        if ($remember) { 
                            setcookie("email", $email, time() + (86400 * 30), "/"); // 30 days 
                            setcookie("password", $password, time() + (86400 * 30), "/"); // 30 days 
                        }

                        // Redirect to the dashboard
                        header("location: dashboard.php");
                        exit;
                    } else {
                        // Invalid password
                        echo "Invalid email or password. <a href='index.php'>Go back</a>";
                    }
                }
            } else {
                // No user found with the given email
                echo "Invalid email or password. <a href='index.php'>Go back</a>";
            }
        } else {
            // Execution error
            echo "Error executing query: " . $stmt->error;
        }

        // Close the statement
        $stmt->close();
    } else {
        // Error preparing the SQL statement
        echo "Error preparing query: " . $conn->error;
    }

    // Close the connection
    $conn->close();
}
?>
