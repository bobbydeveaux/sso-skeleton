<?php

require_once __DIR__.'/bootstrap.php';

use Silex\Application;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

use DVO\OAuth2;
use DVO\Provider\PdoServiceProvider;
use Igorw\Silex\ConfigServiceProvider;

$app            = new Application();
$app['debug']   = true;

$app->register(new Silex\Provider\ServiceControllerServiceProvider());
$app->register(new Igorw\Silex\ConfigServiceProvider(
    __DIR__."/../config/" . APPLICATION_ENV . ".json"
));

$app['oauth2storage'] = $app->share(function() use ($app) {
    return new \DVO\OAuth2\OAuth2StoragePDO($app['pdo']);
});

$app['oauth2'] = $app->share(function() use ($app) {
    return new OAuth2($app['oauth2storage']);
});

$app['authorization.controller'] = $app->share(function() use ($app) {
    return new DVO\Controller\AuthorizationController();
});

$app['token.controller'] = $app->share(function() use ($app) {
    return new DVO\Controller\TokenController();
});


$app->get('/', function() use ($app) {
    try {
        return new Response(
            'SSO is stable (' . gethostname() . ')<br />All services are operational.',
            200
        );
    } catch (Exception $ex) {
        mail("team@dvomedia.com", '[sso-skeleton] Failure with ' . gethostname(), $ex->getMessage());
    }

    return new Response('Sorry, we are currently experiencing problems with (' . gethostname() . ')', 503);

});

$app->register(
    new PdoServiceProvider(),
    array(
        'pdo.dsn' => $app['config']['pdo.dsn'],
        'pdo.username' => $app['config']['pdo.username'],
        'pdo.password' => $app['config']['pdo.password'],
        'pdo.options' => array( // optional
            PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES 'UTF8'",
            PDO::ATTR_TIMEOUT => $app['config']['pdo.timeout'],
        )
    )
);

$app->get('/token', "token.controller:indexJsonAction");
$app->get('/authorization', "authorization.controller:indexJsonAction");

return $app;
