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
	const BODY_TOO_LONG = 12;
	const SERVER_DETAIL_PARSE_FAILED = 13;

	const ADDRESS_VALIDATION_FAILED = 14;
	const IPV6_IS_NOT_SUPPORTED = 140;
	const DOMAIN_VALIDATION_FAILED = 141;
	const HOST_DOES_NOT_EXIST = 142;
	const PRIVATE_IP_RANGE = 143;

	const PORT_VALIDATION_FAILED = 15;
	const BODY_NOT_PROVIDED = 16;
	const INVALID_BODY_FORMAT = 17;
	const INVALID_FORMAT = 18;

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

class Validate
{
	public static function domain($domain)
	{
		// http://stackoverflow.com/a/4694816
		return (preg_match("/^([a-z\d](-*[a-z\d])*)(\.([a-z\d](-*[a-z\d])*))*$/i", $domain) //valid chars check
			&& preg_match("/^.{1,253}$/", $domain) //overall length check
			&& preg_match("/^[^\.]{1,63}(\.[^\.]{1,63})*$/", $domain)   ); //length of each label
	}

	// Unfortunately doesn't support AAAA records yet.
	public static function host($host)
	{
		//These processes should all have been done beforehand but...
		//If host is IP based, then of course it exists, it's not a domain at all!
		if(static::ip($host) === true)
		{
			return true;
		}

		//If domain validation fails
		if(static::domain($host) === false)
		{
			return false;
		}

		$ipv4 = gethostbyname($host);

		return !($host === $ipv4);
	}

	//Both IPv4 and IPv6
	public static function ip($ip, $include_priv = false)
	{
		if($include_priv == true)
		{
			if(filter_var($ip, FILTER_VALIDATE_IP) !== false)
			{
				return true;
			}
			else
			{
				return false;
			}
		}
		else
		{
			if(filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false)
			{
				return true;
			}
			else
			{
				return false;
			}
		}
	}

	public static function ipv4($ip, $include_priv = false)
	{
		if($include_priv == true)
		{
			if(filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false)
			{
				return true;
			}
			else
			{
				return false;
			}
		}
		else
		{
			if(filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false)
			{
				return true;
			}
			else
			{
				return false;
			}
		}
	}

	public static function ipv6($ip, $include_priv = false)
	{
		if($include_priv == true)
		{
			if(filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false)
			{
				return true;
			}
			else
			{
				return false;
			}
		}
		else
		{
			if(filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false)
			{
				return true;
			}
			else
			{
				return false;
			}
		}
	}

	/**
	 * @param Slim $app
	 * @param string $address
	 * @returns string The clean IPv4 address
	 */
	public static function addressWithOutput($app, $address)
	{
		if(Validate::ipv6($address) === true)
		{
			$app->halt(400, json_encode([
				"error" => [
					"code" => Error::IPV6_IS_NOT_SUPPORTED,
					"message" => "IPv6 is currently not supported."
				]
			]));
		}

		if(Validate::ipv4($address, true) === true)
		{
			if(Validate::ipv4($address) === true)
			{
				return $address;
			}
			else
			{
				$app->halt(400, json_encode([
					"error" => [
						"code" => Error::PRIVATE_IP_RANGE,
						"message" => "The provided IP address appears to be in a private or reserved IP range."
					]
				]));
			}
		}

		if(Validate::domain($address) === true)
		{
			if(Validate::host($address) === true)
			{
				$ipv4 = gethostbyname($address);

				if(Validate::ipv4($ipv4) === true)
				{
					return $ipv4;
				}
				else
				{
					$app->halt(400, json_encode([
						"error" => [
							"code" => Error::PRIVATE_IP_RANGE,
							"message" => "The provided host appears to be in a private or reserved IP range."
						]
					]));
				}
			}
			else
			{
				$app->halt(400, json_encode([
					"error" => [
						"code" => Error::HOST_DOES_NOT_EXIST,
						"message" => "The provided host does not exist. (No A record.)"
					]
				]));
			}
		}
		else
		{
			$app->halt(400, json_encode([
				"error" => [
					"code" => Error::DOMAIN_VALIDATION_FAILED,
					"message" => "The validation of the provided domain failed."
				]
			]));
		}

		throw new LogicException("Address Validation did not complete fully.");
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

//TODO: Allow multiple XFF values, use latest one. explode with ', '
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

		//Suppress Exception
		$command = @hex2bin(trim($app->request()->getBody()));

		if($command === false)
		{
			$app->halt(400, json_encode([
				"error" => [
					"code" => Error::INVALID_BODY_FORMAT,
					"message" => "The request body appears to be in a bad format."
				]
			]));
		}

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
					"code" => Error::BODY_TOO_LONG,
					"message" => "The provided request body was too long."
				]
			]));
		}

		if($command === "")
		{
			$app->halt(400, json_encode([
				"error" => [
					"code" => Error::BODY_NOT_PROVIDED,
					"message" => "The request body is required for this route, but was not provided."
				]
			]));
		}

		//From: 3132372e302e302e313a3139313332
		//Suppress Exception
		$serverAddressAndPort = @hex2bin($serverHex);
		//To: 127.0.0.1:19132

		if($serverAddressAndPort === false)
		{
			$app->halt(400, json_encode([
				"error" => [
					"code" => Error::INVALID_FORMAT,
					"message" => "One or more of your non-body arguments appear to be in a bad format."
				]
			]));
		}

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

		$serverAddress[0] = Validate::addressWithOutput($app, $serverAddress[0]);

		if(ctype_digit($serverAddress[1]) === false or ((integer) $serverAddress[1] < 0) or ((integer) $serverAddress[1] > 65535))
		{
			$app->halt(400, json_encode([
				"error" => [
					"code" => Error::PORT_VALIDATION_FAILED,
					"message" => "The validation of the provided IP port failed."
				]
			]));
		}

		$server = new stdClass();
		$server->address = $serverAddress[0];
		$server->port = $serverAddress[1];

		RateLimit::attemptServer($server->address);

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
								"This could be due to the an IP ban against the WebRcon.io servers."
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
		//Suppress Exception
		$serverAddressAndPort = @hex2bin($serverHex);
		//To: 127.0.0.1:19132

		if($serverAddressAndPort === false)
		{
			$app->halt(400, json_encode([
				"error" => [
					"code" => Error::INVALID_FORMAT,
					"message" => "One or more of your non-body arguments appear to be in a bad format."
				]
			]));
		}

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

		$serverAddress[0] = Validate::addressWithOutput($app, $serverAddress[0]);

		if(ctype_digit($serverAddress[1]) === false or ((integer) $serverAddress[1] < 0) or ((integer) $serverAddress[1] > 65535))
		{
			$app->halt(400, json_encode([
				"error" => [
					"code" => Error::PORT_VALIDATION_FAILED,
					"message" => "The validation of the provided IP port failed."
				]
			]));
		}

		$server = new stdClass();
		$server->address = $serverAddress[0];
		$server->port = $serverAddress[1];

		RateLimit::attemptServer($server->address);

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
								"This could be due to the an IP ban against the WebRcon.io servers."
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

$app->post("/validate/address", "rateLimit", function () use ($app) {
	//Suppress Exception
	$address = @hex2bin(trim($app->request()->getBody()));

	if($address === false)
	{
		$app->halt(400, json_encode([
			"error" => [
				"code" => Error::INVALID_BODY_FORMAT,
				"message" => "The request body appears to be in a bad format."
			]
		]));
	}

	if($address === "")
	{
		$app->halt(400, json_encode([
			"error" => [
				"code" => Error::BODY_NOT_PROVIDED,
				"message" => "The request body is required for this route, but was not provided."
			]
		]));
	}

	if(mb_strlen($address) > 256)
	{
		$app->halt(400, json_encode([
			"error" => [
				"code" => Error::BODY_TOO_LONG,
				"message" => "The provided request body was too long."
			]
		]));
	}

	if(Validate::addressWithOutput($app, $address)) // If a string is returned
	{
		echo json_encode([
			"valid" => true
		]);
	}
});

$app->run();