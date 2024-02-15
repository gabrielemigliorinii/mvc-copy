<?php

    define('__ROOT__', '../');

    require_once __ROOT__ . 'model/ds/http_response.php';
    require_once __ROOT__ . 'model/ds/token.php';
    require_once __ROOT__ . 'model/models/email_verify.php';
    require_once __ROOT__ . 'model/models/user.php';
    require_once __ROOT__ . 'model/ds/mail.php';
    require_once __ROOT__ . 'model/ds/mypdo.php';

    main();

    function main()
    {
        if (isset($_SERVER['REQUEST_METHOD']))
        {
            switch ($_SERVER['REQUEST_METHOD'])
            {
                case 'GET': {
                    handle_get();
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

    function handle_get()
    {
        session_start();

        if (!(isset($_SESSION['EMAIL']) && isset($_SESSION['VERIFY_PAGE_STATUS'])))
        {
            session_destroy();
            http_response::client_error(401);
        }

        if ($_SESSION['VERIFY_PAGE_STATUS'] !== 'SIGNIN_WITH_EMAIL_NOT_VERIFIED')
        {
            session_destroy();
            http_response::client_error(401);
        }

        $user = new User(email: $_SESSION['EMAIL']);
        $user->set_id($user->sel_id_from_email());

        $tkn = new token(100);
        $everify = new EmailVerify(tkn_hash:$tkn->hashed(), id_user:$user->get_id());
        $everify->ins();

        if (MyMail::send_email_verify($user->get_email(), (string)$tkn))
        {
            $_SESSION['VERIFY_PAGE_STATUS'] = 'VERIFY_EMAIL_SENT_NF';
            unset($_SESSION['EMAIL']);

            header("location:". $_ENV['DOMAIN'] . '/view/pages/verify/index.php');
            exit;
        }
        else
            http_response::server_error(500);
    }


?>