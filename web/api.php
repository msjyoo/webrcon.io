<?php
require_once(__DIR__ . "/../vendor/autoload.php");

use Slim\Middleware;

//Fix for https://github.com/codeguy/Slim/pull/993 until new version is released
$obj = new Slim\Http\Response();
$refObject = new ReflectionObject($obj);
$refProperty = $refObject->getProperty("messages");
$refProperty->setAccessible(true);
$array = $refProperty->getValue(null);
$array[429] = '429 Too Many Requests';
$refProperty->setValue(null, $array);
unset($obj, $refObject, $refProperty, $array);

$CLOUDFLARE_IP_ADDRESS_RANGE_IPV4 = [
	"199.27.128.0/21",
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/12"
];

function cidr_match($ip, $cidr)
{
	list($subnet, $mask) = explode('/', $cidr);

	if((ip2long($ip) & ~((1 << (32 - $mask)) - 1) ) == ip2long($subnet))
	{
		return true;
	}

	return false;
}

function isTrustedSource($ip)
{
	global $CLOUDFLARE_IP_ADDRESS_RANGE_IPV4;

	foreach($CLOUDFLARE_IP_ADDRESS_RANGE_IPV4 as $cidr)
	{
		if(cidr_match($ip, $cidr))
		{
			return true;
		}
	}

	return false;
}

/** @property Redis $redis */
class Slim extends Slim\Slim {}

class Error
{
	// Validation Errors
	const AUTH_TOKEN_NOT_PROVIDED = 10;
	const AUTH_TOKEN_TOO_LONG = 11;
	const COMMAND_TOO_LONG = 12;
	const SERVER_DETAIL_PARSE_FAILED = 13;
	const IP_VALIDATION_FAILED = 14;
	const PORT_VALIDATION_FAILED = 15;
	const COMMAND_NOT_PROVIDED = 16;

	// Remote Host Errors
	const TIMEOUT_CONNECT = 20;
	const INVALID_PACKET = 21;
	const BAD_PASSWORD = 22;
	const BANNED = 23;
	const BAD_RESPONSE = 24;

	// Rate Limiting Errors
	const TOO_MANY_REQUESTS = 30;
	const TOO_MANY_REQUESTS_SERVER = 31;
}

class HTTPTokenAuthMiddleware extends Middleware
{
	public function call()
	{
		$request = $this->app->request();

		if($request->headers->get("Authorization") === NULL or substr($request->headers->get("Authorization"), 0, 5) !== "token")
		{
			$this->next->call();
			return; // Not HTTP Token Authentication - Bypass
		}

		$token = trim(substr($request->headers->get("Authorization"), 6));

		$this->app->container->set("token", $token);

		$this->next->call();
	}
}

class HTTPMethodHEADStripBodyMiddleware extends Middleware
{
	public function call()
	{
		$request = $this->app->request();

		$this->next->call();

		if($request->getMethod() === "HEAD")
		{
			$this->app->response->setBody("");
		}
	}
}

/*
 * Two types of rate limiting: one for the connecting client, and one for the server host.
 *
 * This is so that an attacker cannot use us as a reflector using multiple IPs.
 */
class RateLimit
{
	public static function attemptServer($ip)
	{
		/** @var Slim $app */
		$app = Slim::getInstance();

		$shortIP = ip2long($ip);

		if($shortIP === false)
		{
			// It should have been validated before-hand.
			throw new LogicException("Server IP is not a valid IP address for rate limiting.");
		}

		if(($count = $app->redis->get("ratelimit:server:{$shortIP}")) !== false)
		{
			if($count >= 6) // 6 requests in 3 seconds
			{
				$app->halt(429, json_encode([
					"error" => [
						"code" => Error::TOO_MANY_REQUESTS_SERVER,
						"message" => "You have exceeded your maximum allowed requests per second to the specified host."
					]
				])); // HTTP/1.1 429 Too Many Requests (RFC 6585)
			}
			else
			{
				$app->redis->incr("ratelimit:server:{$shortIP}");
			}
		}
		else
		{
			//Key didn't exist
			$app->redis->multi(); // Atomic Operation
			$app->redis->incr("ratelimit:server:{$shortIP}");
			$app->redis->expire("ratelimit:server:{$shortIP}", 3);
			$app->redis->exec(); // We could use a SET with a timeout instead bu meh, until it becomes a bottleneck...
		}
	}
}

function requireTokenAuth ()
{
	$app = Slim::getInstance();

	if(!$app->container->has("token"))
	{
		$app->halt(401, json_encode([
			"error" => [
				"code" => Error::AUTH_TOKEN_NOT_PROVIDED,
				"message" => "Authorization Token is required for this route, but was not provided."
			]
		]));
	}
}

function rateLimit()
{
	/** @var Slim $app */
	$app = Slim::getInstance();

	$shortIP = ip2long($app->request()->getIp());

	if($shortIP === false)
	{
		throw new RuntimeException("Remote IP is not a valid IP address for rate limiting.");
	}

	if(($count = $app->redis->get("ratelimit:client:{$shortIP}")) !== false)
	{
		if($count >= 2) // How many requests in a given timeframe
		{
			$app->halt(429, json_encode([
				"error" => [
					"code" => Error::TOO_MANY_REQUESTS,
					"message" => "You have exceeded your maximum allowed requests per second."
				]
			])); // HTTP/1.1 429 Too Many Requests (RFC 6585)
		}
		else
		{
			$app->redis->incr("ratelimit:client:{$shortIP}");
		}
	}
	else
	{
		//Key didn't exist
		$app->redis->multi(); // Atomic Operation
		$app->redis->incr("ratelimit:client:{$shortIP}");
		$app->redis->expire("ratelimit:client:{$shortIP}", 3); // Timeframe
		$app->redis->exec(); // We could use a SET with a timeout instead bu meh, until it becomes a bottleneck...
	}
}

$mode = "production";

if(!isset($_ENV["SLIM_APP_MODE"]) or $_ENV["SLIM_APP_MODE"] !== "production")
{
	if(isset($_ENV["SLIM_APP_MODE"]))
	{
		$mode = strtolower($_ENV["SLIM_APP_MODE"]);
	}
	else
	{
		$mode = "development";
	}
}

// XFF because PagodaBox overrides it
if($mode === "production")
{
	if(!isset($_SERVER['HTTP_X_FORWARDED_FOR']))
	{
		throw new LogicException("PagodaBox Will Always Inject X-Forwarded-For");
	}

	if(isTrustedSource($_SERVER['HTTP_X_FORWARDED_FOR']))
	{
		// Not a typo, Slim prefers X_ before HTTP_X_
		$_SERVER['X_FORWARDED_FOR'] = $_SERVER['HTTP_CF_CONNECTING_IP'];
	}
	else
	{
		//Still overwrite because X_ can be spoofed.
		$_SERVER['X_FORWARDED_FOR'] = $_SERVER['HTTP_X_FORWARDED_FOR'];
	}
}

$app = new Slim(array(
	"mode" => $mode,
	"debug" => false
));

if($app->config("mode") === "development")
{
	$app->config("debug", true);

	$_ENV["CACHE1_HOST"] = "192.168.137.5";
	$_ENV["CACHE1_PORT"] = 6379;
}

$app->add(new HTTPTokenAuthMiddleware);
$app->add(new HTTPMethodHEADStripBodyMiddleware);

/** @property Redis $redis */
$app->redis = new Redis;
$app->redis->connect($_ENV["CACHE1_HOST"], $_ENV["CACHE1_PORT"], 2);

$app->group("/:serverHex", function () use ($app) {
	$app->post('/rcon', "requireTokenAuth", "rateLimit", function ($serverHex) use ($app) {
		$sourceQuery = new SourceQuery;

		$token = $app->container->get("token");

		$command = hex2bin(trim($app->request()->getBody()));

		// If RCON password is longer than 4096 bytes, it's probably a buffer overflow attack using
		// our service as a reflector.
		if(mb_strlen($token) > 4096)
		{
			$app->halt(400, json_encode([
				"error" => [
					"code" => Error::AUTH_TOKEN_TOO_LONG,
					"message" => "The provided Authorization Token was too long."
				]
			]));
		}

		// Similar to above
		if(mb_strlen($command) > 4096)
		{
			$app->halt(400, json_encode([
				"error" => [
					"code" => Error::COMMAND_TOO_LONG,
					"message" => "The provided request body (the command) was too long."
				]
			]));
		}

		if($command === "")
		{
			$app->halt(400, json_encode([
				"error" => [
					"code" => Error::COMMAND_NOT_PROVIDED,
					"message" => "The request body (the command) was not provided."
				]
			]));
		}

		//From: 3132372e302e302e313a3139313332
		$serverAddressAndPort = hex2bin($serverHex);
		//To: 127.0.0.1:19132

		$serverAddress = explode(":", $serverAddressAndPort);

		// Validate User Input
		if(count($serverAddress) !== 2 or !isset($serverAddress[0]) or !isset($serverAddress[1]))
		{
			$app->halt(400, json_encode([
				"error" => [
					"code" => Error::SERVER_DETAIL_PARSE_FAILED,
					"message" => "There was an issue with parsing the provided server details."
				]
			]));
		}

		if(filter_var($serverAddress[0], FILTER_VALIDATE_IP) === false)
		{
			$app->halt(400, json_encode([
				"error" => [
					"code" => Error::IP_VALIDATION_FAILED,
					"message" => "The validation of the provided IP address failed."
				]
			]));
		}

		if(ctype_digit($serverAddress[1]) === false or ((integer) $serverAddress[1] < 0) or ((integer) $serverAddress[1] > 65535))
		{
			$app->halt(400, json_encode([
				"error" => [
					"code" => Error::PORT_VALIDATION_FAILED,
					"message" => "The validation of the provided IP address failed."
				]
			]));
		}

		$server = new stdClass();
		$server->address = $serverAddress[0];
		$server->port = $serverAddress[1];

		RateLimit::attemptServer($server->address);//TODO: Move failure logic out

		try
		{
			$sourceQuery->Connect($server->address, $server->port, 3, SourceQuery::SOURCE);
			$sourceQuery->SetRconPassword($token);

			$result = trim($sourceQuery->Rcon($command));

			$sourceQuery->Disconnect();
		}
			//catch(\xPaw\SourceQuery\Exception\InvalidArgumentException $e) // Don't catch this so it errors out
			//catch(\xPaw\SourceQuery\Exception\SocketException $e) // Don't catch this so it errors out
		catch(\xPaw\SourceQuery\Exception\TimeoutException $e)
		{
			switch($e->getCode())
			{
				case \xPaw\SourceQuery\Exception\TimeoutException::TIMEOUT_CONNECT:
					$app->halt(504, json_encode([
						"error" => [
							"code" => Error::TIMEOUT_CONNECT,
							"message" => "The attempt to connect to the provided server timed out."
						]
					])); // HTTP/1.1 504 Gateway Timeout
					break;
				default:
					throw new LogicException("Unknown TiemoutException Exception Code");
			}
		}
		catch(\xPaw\SourceQuery\Exception\InvalidPacketException $e)//Bad packet from game server
		{
			$app->halt(502, json_encode([
				"error" => [
					"code" => Error::INVALID_PACKET,
					"message" => "The provided server responded with an invalid packet."
				]
			])); // HTTP/1.1 502 Bad Gateway
		}
		catch(\xPaw\SourceQuery\Exception\AuthenticationException $e)
		{
			switch($e->getCode())
			{
				case \xPaw\SourceQuery\Exception\AuthenticationException::BAD_PASSWORD:
					$app->halt(401, json_encode([
						"error" => [
							"code" => Error::BAD_PASSWORD,
							"message" => "The authentication against the provided server with the given credentials failed."
						]
					])); // HTTP/1.1 401 Unauthorized
					break;
				case \xPaw\SourceQuery\Exception\AuthenticationException::BANNED:
					$app->halt(403, json_encode([
						"error" => [
							"code" => Error::BANNED,
							"message" => "The provided server actively refused connection against the specific client. ".
								"This could be due to the an IP ban against the WebRCON servers."
						]
					])); // HTTP/1.1 403 Forbidden
					break;
				default:
					throw new LogicException("Unknown AuthenticationException Exception Code");
			}
		}

		if(isset($result) and $result !== false)
		{
			// Note here that $result could be an empty string

			$result = str_replace("\r\n", "\n", $result);
			$output = explode("\n", $result);

			echo json_encode([
				"response" => $output// Each new line is on a new array key
			]);
		}
		else
		{
			$app->halt(502, json_encode([
				"error" => [
					"code" => Error::BAD_RESPONSE,
					"message" => "The provided server responded with an invalid response (false) to the provided command."
				]
			])); // HTTP/1.1 502 Bad Gateway :D
		}
	});

	$app->post('/authenticate', "requireTokenAuth", "rateLimit", function ($serverHex) use ($app) {
		$sourceQuery = new SourceQuery;

		$token = $app->container->get("token");

		// If RCON password is longer than 4096 bytes, it's probably a buffer overflow attack using
		// our service as a reflector.
		if(mb_strlen($token) > 4096)
		{
			$app->halt(400, json_encode([
				"error" => [
					"code" => Error::AUTH_TOKEN_TOO_LONG,
					"message" => "The provided Authorization Token was too long."
				]
			]));
		}

		//From: 3132372e302e302e313a3139313332
		$serverAddressAndPort = hex2bin($serverHex);
		//To: 127.0.0.1:19132

		$serverAddress = explode(":", $serverAddressAndPort);

		// Validate User Input
		if(count($serverAddress) !== 2 or !isset($serverAddress[0]) or !isset($serverAddress[1]))
		{
			$app->halt(400, json_encode([
				"error" => [
					"code" => Error::SERVER_DETAIL_PARSE_FAILED,
					"message" => "There was an issue with parsing the provided server details."
				]
			]));
		}

		if(filter_var($serverAddress[0], FILTER_VALIDATE_IP) === false)
		{
			$app->halt(400, json_encode([
				"error" => [
					"code" => Error::IP_VALIDATION_FAILED,
					"message" => "The validation of the provided IP address failed."
				]
			]));
		}

		if(ctype_digit($serverAddress[1]) === false or ((integer) $serverAddress[1] < 0) or ((integer) $serverAddress[1] > 65535))
		{
			$app->halt(400, json_encode([
				"error" => [
					"code" => Error::PORT_VALIDATION_FAILED,
					"message" => "The validation of the provided IP address failed."
				]
			]));
		}

		$server = new stdClass();
		$server->address = $serverAddress[0];
		$server->port = $serverAddress[1];

		RateLimit::attemptServer($server->address);//TODO: Move failure logic out

		try
		{
			$sourceQuery->Connect($server->address, $server->port, 3, SourceQuery::SOURCE);
			$sourceQuery->SetRconPassword($token);

			$sourceQuery->Disconnect();
		}
			//catch(\xPaw\SourceQuery\Exception\InvalidArgumentException $e) // Don't catch this so it errors out
			//catch(\xPaw\SourceQuery\Exception\SocketException $e) // Don't catch this so it errors out
		catch(\xPaw\SourceQuery\Exception\TimeoutException $e)
		{
			switch($e->getCode())
			{
				case \xPaw\SourceQuery\Exception\TimeoutException::TIMEOUT_CONNECT:
					$app->halt(504, json_encode([
						"error" => [
							"code" => Error::TIMEOUT_CONNECT,
							"message" => "The attempt to connect to the provided server timed out."
						]
					])); // HTTP/1.1 504 Gateway Timeout
					break;
				default:
					throw new LogicException("Unknown TiemoutException Exception Code");
			}
		}
		catch(\xPaw\SourceQuery\Exception\InvalidPacketException $e)//Bad packet from game server
		{
			$app->halt(502, json_encode([
				"error" => [
					"code" => Error::INVALID_PACKET,
					"message" => "The provided server responded with an invalid packet."
				]
			])); // HTTP/1.1 502 Bad Gateway
		}
		catch(\xPaw\SourceQuery\Exception\AuthenticationException $e)
		{
			switch($e->getCode())
			{
				case \xPaw\SourceQuery\Exception\AuthenticationException::BAD_PASSWORD:
					$app->halt(401, json_encode([
						"error" => [
							"code" => Error::BAD_PASSWORD,
							"message" => "The authentication against the provided server with the given credentials failed."
						]
					])); // HTTP/1.1 401 Unauthorized
					break;
				case \xPaw\SourceQuery\Exception\AuthenticationException::BANNED:
					$app->halt(403, json_encode([
						"error" => [
							"code" => Error::BANNED,
							"message" => "The provided server actively refused connection against the specific client. ".
								"This could be due to the an IP ban against the WebRCON servers."
						]
					])); // HTTP/1.1 403 Forbidden
					break;
				default:
					throw new LogicException("Unknown AuthenticationException Exception Code");
			}
		}

		echo json_encode([
			"authenticated" => true
		]);
	});
});

$app->get("/test/getip", function () use ($app) {
	echo $app->request()->getIp();
});

$app->run();