<?php

    define('__ROOT__', '../'); 

    require_once __ROOT__ . 'model/ds/http_response.php';
    require_once __ROOT__ . 'model/ds/file_system_handler.php';
    require_once __ROOT__ . 'model/ds/token.php';
    require_once __ROOT__ . 'model/ds/mypdo.php';
    require_once __ROOT__ . 'model/ds/functions.php';
    require_once __ROOT__ . 'model/ds/mail.php';
    require_once __ROOT__ . 'model/models/user.php';
    require_once __ROOT__ . 'model/models/email_verify.php';
    require_once __ROOT__ . 'model/models/user_security.php';
    require_once __ROOT__ . 'model/ds/two_factor_auth.php';
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
        if (count($_POST) === 4 && key_contains($_POST, 'email', 'name', 'surname', 'pwd'))
        {
            htmlspecialchars_array($_POST);

            if (!filter_var($_POST['email'], FILTER_VALIDATE_EMAIL))
                http_response::client_error(400, "Invalid email format");

            if (strlen($_POST['pwd']) < 1)
                http_response::client_error(400, "Password too short");

            handle_user_insertion($_POST['email'], $_POST['name'], $_POST['surname'], $_POST['pwd']);
        }
        else 
        { 
            http_response::client_error(404); 
        }
    }

    function handle_user_insertion(string $email, string $name, string $surname, string $input_pwd)
    {
        $user = new User(email:$email,name:$name,surname:$surname);

        $id_user = $user->sel_id_from_email();

        if ($id_user === false)
            http_response::server_error();
        
        if ($id_user !== -1)
            http_response::client_error(400, "Email already taken");
        
        unset($id_user);

        mypdo::connect('insert');
        mypdo::begin_transaction();
        
        if (!$user->ins())
        {
            mypdo::roll_back();
            http_response::server_error(500);
        }

        $user->sel_id_from_email();

        file_system_handler::mk_user_storage_dir($user->get_email(), __ROOT__ . 'users_storage/');
        
        $tkn = new token(100);
        $e_verify = new EmailVerify
        (
            tkn_hash: $tkn->hashed(), 
            id_user: $user->get_id()
        );

        if (!$e_verify->ins())
        {
            mypdo::roll_back();
            http_response::server_error();
        }

        /*$email_sent = MyMail::send_email_verify($user->get_email(), (string)$tkn);
        if ($email_sent === false)
            http_response::client_error(400, "There is an issue with the provided email address, it may not exist.");
        */

        $user_keys = UserKeysHandler::get_new_instance_from_pwd($input_pwd);
        
        $user_security_data = new UserSecurity
        (
            pwd_hash:               $user_keys->get_pwd_hashed(),
            rkey_hash:              $user_keys->get_rkey_hashed(),
            rkey_encrypted:         $user_keys->get_rkey_encrypted(),
            ckey_encrypted:         $user_keys->get_ckey_encrypted(),
            secret_2fa_encrypted:   $user_keys->get_secret_2fa_encrypted(),
            dkey_salt:              $user_keys->get_dkey_salt(),
            id_user:                $user->get_id()
        );

        if (!$user_security_data->ins())
        {
            mypdo::roll_back();
            http_response::server_error();
        }

        mypdo::commit();

        session_start();
        $_SESSION['VERIFY_PAGE_STATUS'] = 'SIGNUP_OK';
    
        $redirect_url = $_ENV['DOMAIN'] . '/view/pages/verify/index.php';
            
        http_response::successful(200, false, array("redirect" => $redirect_url));
    }

?>
