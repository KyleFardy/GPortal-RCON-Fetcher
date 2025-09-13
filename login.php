<?php
include "includes/classes/gportal.class.php";

$gportal = new GPORTAL_AUTH();
if ($gportal->checkLoginStatus()) {
    $gportal->redirect("/");
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>G-Portal Login</title>
    <meta name="csrf-token" content="<?= $gportal->generateCsrfToken(); ?>">
    <link href="/assets/bootstrap/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="/assets/css/custom.css?v=<?= time() ?>" rel="stylesheet">
</head>

<body data-bs-theme="dark">
    <div class="container">
        <div class="d-flex align-items-center justify-content-center min-vh-100">
            <div class="card login-card p-4">
                <h4 class="text-center mb-3">Login To G-Portal</h4>
                <div class="alert alert-info small text-center" role="alert">
                    This Website Does Not Store Any Credentials<br>Your Email And Password Are Only Used To Temporarily Fetch Server Data From G-Portal
                </div>
                <div class="mb-3 text-center">
                    <label for="email" class="form-label text-center">Email Address</label>
                    <input type="email" class="form-control text-center" id="email" name="email" required placeholder="your@email.com">
                </div>
                <div class="mb-3 text-center">
                    <label for="password" class="form-label text-center">Password</label>
                    <input type="password" class="form-control text-center" id="password" name="password" required placeholder="••••••••">
                </div>
                <button type="button" id="login-button" name="login-button" class="btn btn-primary w-100">Login</button>

                <a href="//github.com/KyleFardy/GPortal-RCON-Fetcher" target="_blank" class="btn btn-success w-100 mt-2">
                    <i class="fa-brands fa-github"></i> View GitHub
                </a>

            </div>
        </div>
    </div>

    <script src="/assets/jquery/js/jquery.min.js"></script>
    <script src="/assets/sweetalert/js/sweetalert.js"></script>
    <script src="/assets/bootstrap/js/bootstrap.bundle.min.js"></script>
    <script src="/assets/js/custom.js?v=<?= time() ?>"></script>
</body>

</html>