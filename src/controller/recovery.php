<?php


    define('__ROOT__', '../'); 

    require_once __ROOT__ . 'model/ds/http_response.php';
    require_once __ROOT__ . 'model/ds/mypdo.php';
    require_once __ROOT__ . 'model/models/user_security.php';
    require_once __ROOT__ . 'model/models/user.php';
    require_once __ROOT__ . 'model/ds/functions.php';
    require_once __ROOT__ . 'model/ds/user_keys_handler.php';

    main();
        
    function main()
    {
        if (isset($_SERVER['REQUEST_METHOD']))
        {
            switch ($_SERVER['REQUEST_METHOD'])
            {
                case 'POST': {
                    handle_post();
                    break;
                }
    
                default: {
                    http_response::client_error(405, $_SERVER['REQUEST_METHOD']);
                }
            }
        }
        else
        {
            http_response::server_error(500);
        }
    }


    function handle_post()
    {
        htmlspecialchars_array($_POST);

        if (count($_POST) === 2 && key_contains($_POST, 'email', 'recovery_key'))
        {
            if (!filter_var($_POST['email'], FILTER_VALIDATE_EMAIL))
                http_response::client_error(400, "Invalid email format");

            handle_rkey_check($_POST['email'], $_POST['recovery_key']);
        }
        else if (count($_POST) === 1 && key_contains($_POST, 'pwd'))
        {
            if (strlen($_POST['pwd']) < 2)
                http_response::client_error(400, "Invalid password format");

            handle_pwd_reset($_POST['pwd']);
        }
        
        else
            http_response::client_error(400, "Invalid request parameters");
    }

    function handle_rkey_check($email, $rkey)
    {
        $user = new User(email:$email);
        $user->sel_id_from_email($user->get_email());
        
        $us = new UserSecurity();

        $us->sel_rkey_hash_from_email
        (
            $user->to_assoc_array(email:true)
        );

        if (!password_verify($rkey, $us->get_rkey_hash()))
            http_response::client_error(400, "The provided recovery key is incorrect. Please double-check the key and try again.");
        
        session_start();
        
        $_SESSION['RECOVERING_ACCOUNT'] = true;
        $_SESSION['ID_USER'] = $user->get_id();
        $_SESSION['RKEY'] = $rkey;

        http_response::successful(200);
    }

    function handle_pwd_reset($pwd)
    {
        // check auth
        session_start();

        if ((isset($_SESSION['RECOVERING_ACCOUNT']) && isset($_SESSION['ID_USER']) && isset($_SESSION['RKEY'])) === false)
        {
            session_destroy();
            http_response::client_error(401);
        }

        $ukh = new UserKeysHandler();
        
        $ukh->set_pwd($pwd);
        $ukh->set_dkey_salt_random();
        $ukh->set_dkey_auto();
        $ukh->set_rkey($_SESSION['RKEY']);

        $us = new UserSecurity
        (
            pwd_hash:       $ukh->get_pwd_hashed(),
            rkey_encrypted: $ukh->get_rkey_encrypted(),
            dkey_salt:      $ukh->get_dkey_salt(),
            id_user:        $_SESSION['ID_USER']
        );

        $status = $us->upd_pwdhash_rkeyc_dkeysalt_from_iduser();

        session_destroy();
        
        if ($status === false)
            http_response::server_error();

        http_response::successful();
    }

?>