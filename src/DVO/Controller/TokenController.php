<?php

namespace DVO\Controller;

use Silex\Application;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\JsonResponse;

use OAuth2\OAuth2;

class TokenController extends AbstractController
{
    /**
     * Handles the HTTP GET.
     *
     * @param Request     $request The request.
     * @param Application $app     The app.
     *
     * @return JsonResponse
     */
    public function indexJsonAction(Request $request, Application $app)
    {
        // create client
        // wrong controller but prototype
        $create = $request->query->get('create');
        if (false === empty($create)) {
            $clientId     = $request->query->get('client_id');
            $clientSecret = $request->query->get('client_secret');
            $redirectUrl  = $request->query->get('redirect_uri');

            $result = $app['oauth2storage']->addClient($clientId, $clientSecret, $redirectUrl);
            var_dump($result);
            die();
        }

        $response = $app['oauth2']->grantAccessToken();

        return $response;
    }

    /**
     * Handle unexpected responses
     *
     * @param  array        $error
     * @return JsonResponse
     */
    public function errorJsonResponse(array $error)
    {
        return new JsonResponse($error);
    }
}
