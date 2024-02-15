<?php


    define('__ROOT__', '../'); 

    require_once __ROOT__ . 'model/ds/http_response.php';
    require_once __ROOT__ . 'model/ds/two_factor_auth.php';
    require_once __ROOT__ . 'model/ds/mypdo.php';
    require_once __ROOT__ . 'model/ds/crypto.php';
    require_once __ROOT__ . 'model/ds/token.php';
    require_once __ROOT__ . 'model/ds/client.php';
    require_once __ROOT__ . 'model/ds/functions.php';
    require_once __ROOT__ . 'model/models/session.php';
    require_once __ROOT__ . 'model/models/user.php';
    require_once __ROOT__ . 'model/models/user_security.php';
    
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
                    http_response::client_error(405);
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
        if (count($_POST) === 1 && key_contains($_POST, 'otp'))
        {
            htmlspecialchars_array($_POST);

            if (!preg_match('/^\d{6}$/', $_POST['otp']) === 1)
                http_response::client_error(400, "Invalid OTP format"); 

            handle_otp_check($_POST['otp']);
        }
        else 
        { 
            http_response::client_error(404); 
        }
    }

    function handle_otp_check($input_otp)
    {
        $input_otp;

        session_start();

        if (!isset($_SESSION['OTP_CHECKING']))
            http_response::client_error(401);
        
        $user = new User(id: $_SESSION['ID_USER']);
        $user->set_email($user->sel_email_from_id());

        $us = new UserSecurity(id_user:$user->get_id());
        $us->sel_rkey_from_id();
        $us->sel_secret_2fa_c_from_id();
        
        $rkey = crypto::decrypt_AES_GCM($us->get_rkey_encrypted(), $_SESSION['DKEY']);

        $secret_2fa = crypto::decrypt_AES_GCM($us->get_secret_2fa_encrypted(), $rkey);

        $tfa = new MyTFA(email: $user->get_email(), secret: $secret_2fa);

        if ($tfa->codeIsValid($input_otp) === false)
            http_response::client_error(400, "OTP code is wrong");
        
        $_SESSION['AUTH_2FA'] = true;
        $_SESSION['LOGGED'] = true;

        unset($_SESSION['OTP_CHECKING']);

        Session::create_or_load($user->get_id(), client::get_ip());

        http_response::successful
        (
            200, 
            false, 
            array("redirect" => $_ENV['DOMAIN'] . '/view/pages/private/index.php')
        );
    }



?>