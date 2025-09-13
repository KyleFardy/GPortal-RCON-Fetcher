<?php
include "includes/classes/gportal.class.php";

$gportal = new GPORTAL_AUTH();
if (!$gportal->checkLoginStatus()) {
    $gportal->redirect("/login");
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <title>GPortal Info</title>
    <meta name="csrf-token" content="<?= $gportal->generateCsrfToken(); ?>">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="/assets/bootstrap/css/bootstrap.min.css" rel="stylesheet">
    <link href="/assets/datatables/css/datatables.min.css" rel="stylesheet">
    <link href="/assets/css/custom.css?v=<?= time() ?>" rel="stylesheet">
</head>

<body data-bs-theme="dark">
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark border-bottom border-secondary">
        <div class="container-fluid">
            <a class="navbar-brand fw-bold" href="#">GPortal Server Info</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item">
                        <a class="nav-link active" href="/">Dashboard</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link text-danger" href="/logout">Logout</a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>
    <div class="container">
        <div class="row">
            <div class="col-12">
                <div class="d-flex align-items-center">
                    <div class="card server-card p-4 w-100">
                        <h4 class="text-center mb-4">Servers</h4>
                        <div class="alert alert-info small text-center" role="alert">
                            Fetching Servers May Take A Few Minutes If You Have Many!
                        </div>
                        <div class="table-responsive">
                            <table id="servers" class="table table-hover nowrap mb-0" style="width:100%">
                                <thead>
                                    <tr>
                                        <th>Server Name</th>
                                        <th>IP Address</th>
                                        <th>RCON Port</th>
                                        <th>RCON Password</th>
                                    </tr>
                                </thead>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="/assets/jquery/js/jquery.min.js"></script>
    <script src="/assets/sweetalert/js/sweetalert.js"></script>
    <script src="/assets/bootstrap/js/bootstrap.bundle.min.js"></script>
    <script src="/assets/datatables/js/datatables.min.js"></script>
    <script src="/assets/js/custom.js?v=<?= time() ?>"></script>
</body>

</html>