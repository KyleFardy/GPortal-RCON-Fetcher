<?php
session_start();

// Unset All Session Variables
$_SESSION = [];

// Destroy The Session
session_destroy();

// Redirect To Login Page
header("Location: /login");
exit;
