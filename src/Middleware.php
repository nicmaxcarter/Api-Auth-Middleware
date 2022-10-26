<?php

namespace Nicmaxcarter\ApiAuthMiddleware;

use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;
use Slim\Psr7\Response;

class Middleware
{
    private $secret;
    private $lastSecret;

    public function __construct($secretNumber = null)
    {
        $hash = $this->createHash($secretNumber);
        $lastHash = $this->lastHash();

        $this->secret = $hash;
        $this->lastSecret = $lastHash;
    }

    public function __invoke(
        Request $request,
        RequestHandler $handler
    ): Response
    {
        $reqData = json_decode(file_get_contents('php://input'));

        $verify = false;

        if(isset($reqData->secret)){
            $secret = $reqData->secret;

            // accept hashes from the current hour
            if($secret === $this->secret)
                $verify = true;

            // accept hashes from the past hour
            // (10am if it is currenty 11am)
            if($secret === $this->lastSecret)
                $verify = true;
        }

        if(!$verify) {
            throw new \Slim\Exception\HttpForbiddenException($request);
        }

        // we handle the request AFTER the exception is thrown to prevent
        // scripts from running and THEN thowing exception.
        $response = $handler->handle($request);
        return $response;
    }

    public function getSecret(){
        return $this->secret;
    }

    public function getLastSecret(){
        return $this->lastSecret;
    }

    private function createHash(
        $secretNumber = null,
        $currHour = null,
        $currDay = null
    )
    {
        if(is_null($secretNumber)) {
            $secretNumber = 1*12*13*9*98*97;
        }

        if(is_null($currHour))
            $currHour = $this->getHour();

        if(is_null($currDay))
            $currDay = $this->getDay();

        // special number that will changed based on the hour
        $number = intval($currHour * $secretNumber);

        // non-hashed string
        $calculate = "$number#$currDay!";

        // hashed text
        return hash('sha1', $calculate);
    }

    private function lastHash()
    {
        $lastHour = $this->getLastHour();

        return $this->createHash($lastHour);
    }

    private function getHour()
    {
        $currHour = intval(date('G')); // current hour as 0-23

        // if the current hour is 0 (12:00am - 12:59am)
        if($currHour === 0)
            // return 24 so that our non hashed string is not too simple
            return 24;

        return $currHour;
    }

    private function getLastHour()
    {
        $currHour = $this->getHour();

        if($currHour === 24)
            return 23;

        return $currHour-1;
    }

    private function getDay()
    {
        return date('l'); // current day as Sunday through Saturday
    }
}
