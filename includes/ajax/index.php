<?php
ini_set("display_errors", 0);
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

ob_start();

include "../classes/gportal.class.php";
$gportal = new GPORTAL_AUTH;

$csrfToken = '';

if (isset($_POST['csrfToken'])) {
    $csrfToken = $_POST['csrfToken'];
} else if (isset($_GET['csrfToken'])) {
    $csrfToken = $_GET['csrfToken'];
}

if (isset($_GET['action'])) {
    switch (strip_tags($_GET['action'])) {
        case "login":
            if (!empty($csrfToken) && $gportal->verifyCsrfToken($csrfToken)) {
                echo $gportal->login($_POST["email"], $_POST["password"]);
            } else {
                header("Content-Type: application/json");
                echo $gportal->jsonResponse(
                    "ERROR",
                    "CSRF Token Verification Failed!<br>Please Refresh The Page And Try Again!",
                    "error"
                );
            }
            break;
        case "getServers":
            if (!empty($csrfToken) && $gportal->verifyCsrfToken($csrfToken)) {
                header("Content-Type: application/json");
                echo $gportal->getServers();
            } else {
                header("Content-Type: application/json");
                echo $gportal->jsonResponse(
                    "ERROR",
                    "CSRF Token Verification Failed!<br>Please Refresh The Page And Try Again!",
                    "error"
                );
                exit();
            }
            break;
        default:
            $gportal->redirect("/");
            break;
    }
}
