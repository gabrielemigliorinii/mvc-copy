<?php

    define('__ROOT__', '..');

    require_once __ROOT__ . '/resource/router.php';
    require_once __ROOT__ . '/src/controller/signup.php';
    require_once __ROOT__ . '/src/controller/base.php';

    $router = Router::getInstance();
    
    $router->addRoute(Router::HTTP_POST, '/login', ['email', 'password'], function() {
        SignupController::renderPageSignup();
    });

    $router->addRoute(Router::HTTP_GET, '/login', [], function() {
        SignupController::renderPageSignup();
    });

    $router->addRoute(Router::HTTP_POST, '/signup', [], function() {
        SignupController::processSignup();
    });

    $router->addRoute(Router::HTTP_GET, '/about', [], function() {
        BaseController::renderPageAbout();
    });

    $router->addRoute(Router::HTTP_GET, '/login/([a-zA-Z0-9]{10,100})', [], function($matches) {
        $token = $matches[1];
        $_GET['token'] = $token;
        include 'login.php';
    });

    $router->addRoute(Router::HTTP_GET, '/login', ['token'], function($matches) {
        $token = $matches[1];
        $_GET['token'] = $token;
        include 'login.php';
    });

    $router->setNotFoundCallback(function () {
        BaseController::renderPageNotFound();
    });

    $method = $_SERVER['REQUEST_METHOD'];
    $path = $_SERVER['REQUEST_URI'];   

    $router->handleRequest($method, $path);

?>