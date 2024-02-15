<?php

    define('__ROOT__', '../');
    
    require_once __ROOT__ . 'model/ds/http_response.php';
    require_once __ROOT__ . 'model/models/user_security.php';
    require_once __ROOT__ . 'model/models/session.php';
    require_once __ROOT__ . 'model/ds/mypdo.php';
    require_once __ROOT__ . 'model/ds/client.php';
    require_once __ROOT__ . 'model/ds/crypto.php';
    require_once __ROOT__ . 'model/ds/functions.php';
    require_once __ROOT__ . 'model/ds/mydatetime.php';
    
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
            // server error...
            http_response::server_error(500);
        }
    }

    function handle_post()
    {   
        if (session_status() !== PHP_SESSION_ACTIVE) 
        session_start();

        if ((isset($_SESSION['LOGGED']) && isset($_SESSION['ID_USER'])) === false)
        {
            session_destroy();
            http_response::client_error(401);
        }

        if (count($_POST) === 1 && isset($_POST['id_session']))
        {
            htmlspecialchars_array($_POST);

            $id_session = $_POST['id_session'];
            $id_user = $_SESSION['ID_USER'];

            $s = new Session(id_session:$id_session, id_user:$id_user);
            $s->set_end();

            $session_expired = $s->expire_from_idsess_iduser();

            if ($session_expired === false)
                http_response::client_error(400, "Invalid session ID");

            // User has sent the id_session, if it equals of the current id session => logout()
            if (strcmp($id_session, $_SESSION['CURRENT_ID_SESSION']) === 0)
            {
                session_destroy();
                http_response::successful
                (
                    200, 
                    false, 
                    array("redirect" => $_ENV['DOMAIN'] . '/view/pages/signin/index.php')
                );
            }
            
            http_response::successful(200);
        }
        else
        {
            http_response::client_error(400, "Invalid request parameters");
        }
    }


?>