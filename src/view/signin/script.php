<?php

    define('__ROOT__', '../../../'); 
    define('__QP__', __ROOT__ . 'sql_qrys/');

    require_once __ROOT__ . 'model/ds/functions.php';
    require_once __ROOT__ . 'model/models/email_verify.php';
    require_once __ROOT__ . 'model/models/user.php';
    require_once __ROOT__ . 'model/ds/mypdo.php';
    require_once __ROOT__ . 'model/ds/token.php';

    function main(&$success, &$error, &$redirect)
    {
        if (isset($_SERVER['REQUEST_METHOD']))
        {
            switch ($_SERVER['REQUEST_METHOD'])
            {
                case 'GET': {
                    handle_get($success, $error, $redirect);
                    break;
                }
    
                default: {
                    http_response::client_error(405);
                    break;
                }
            }
        }
        else
        {
            http_response::server_error(500);
        }
    }

    function handle_get(&$success, &$error, &$redirect)
    {
        if (count($_GET) === 1 && key_contains($_GET, 'tkn'))
        {
            $token = $_GET['tkn'];
            check_email_verify_token($token, $success, $error, $redirect);
        }
        else if (count($_GET) === 0)
        {
            logged_check();
        }
        else
        {
            http_response::client_error(400);
        }
    }

    function check_email_verify_token($token_val, &$success, &$error, &$redirect)
    {
        $tkn = new Token;
        $tkn->set($token_val);

        $e_verify = new EmailVerify(tkn_hash: $tkn->hashed());

        $id_user = $e_verify->sel_id_from_tkn();

        if ($id_user === -1)
        {
            http_response_code(400);
            $error = "Invalid or expired email verify link.";
        }
        else
        {
            if (!session_status()) 
                session_start();

            if (isset($_SESSION['VERIFING_EMAIL']))
                unset($_SESSION['VERIFING_EMAIL']);

            $user = new User(id: $id_user);
            $user->upd_user_verified();

            $e_verify->del_ver_from_tkn();

            $success = "Email verified, login";
        }
        
        $redirect = $_ENV['DOMAIN'] . '/view/pages/signin/index.php';
    }


?>