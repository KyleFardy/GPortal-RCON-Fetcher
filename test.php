<?php
ini_set("display_errors", 1);
include "includes/classes/gportal.class.php";

$gportal = new GPORTAL_AUTH();
if (!$gportal->checkLoginStatus()) {
    $gportal->redirect("/login");
}
$JSON = new StdClass;
foreach ($gportal->fetchServers() as $server) {
    $status = $gportal->fetchStatus($server['serviceId'], $server['region']);
    $JSON->data[] = array(
        "status" => $status,
        "region" => $server['region'],
        "serverId" => $server['serverId'],
        "serviceId" => $server['serviceId'],
    );
}
echo json_encode($JSON);
