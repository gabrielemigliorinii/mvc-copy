<?php

    function key_contains(&$array, ...$args) : bool
    {
        foreach ($args as $arg)
        {
            if (!isset($array[$arg]))
                return false;    
        }
        return true;
    }

    function htmlspecialchars_array(array &$array) : void
    {
        foreach ($array as $key => $val)
            $array[$key] = htmlspecialchars($val);
    }

    function logged_check()
    {
        if (session_status() !== PHP_SESSION_ACTIVE) 
            session_start();

        if (isset($_SESSION['LOGGED']) && isset($_SESSION['ID_USER']))
        {
            header("location: " . $_ENV['DOMAIN'] . '/view/pages/private/index.php');
            exit;
        }
        else 
            session_destroy();
    }

    function complex_end(bool ...$vars) : bool
    {
        foreach ($vars as $var) 
            if (!is_bool($var)) 
                return false;
        return true;
    }


?>