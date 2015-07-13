<?php

namespace DVO\Controller;

use Silex\Application;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\JsonResponse;

use OAuth2\OAuth2;

class AuthorizationController extends AbstractController
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
        $accept = $request->query->get('accept');

        if (false === empty($accept)) {
            $userId = 1; // Use whatever method you have for identifying users.
            try {
                $response = $app['oauth2']->finishClientAuthorization($accept == "yep", $userId);
                return $response;
            } catch (OAuth2ServerException $e) {
                $e->getHttpResponse()->send();
            }

        }

        return new Response(
            $response,
            200,
            [
                'ETag'          => 'PUB' . time(),
                'Last-Modified' => gmdate("D, d M Y H:i:s", time()) . " GMT",
                'Cache-Control' => 'maxage=3600, s-maxage=3600, public',
                'Expires'       => time()+3600]
        );
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
