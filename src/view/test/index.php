<?php
    define('__ROOT__', '../../../');

    require_once __ROOT__ . 'model/ds/mypdo.php';
    require_once __ROOT__ . 'model/models/user.php';
    require_once __ROOT__ . 'model/models/session.php';
    require_once __ROOT__ . 'model/ds/token.php';
    require_once __ROOT__ . 'model/ds/client.php';
    require_once __ROOT__ . 'model/ds/mypdo.php';



    echo "<pre>";
    print_r(in_array("Europe/Rome", timezone_identifiers_list()));
    echo "<pre>";
    
    
    exit;
?>