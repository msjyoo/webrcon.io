var TEXTCOLOUR_RED = "\x1b[31;1m";
var TEXTCOLOUR_GREEN = "\x1b[32;1m";
var TEXTCOLOUR_RESET = "\x1b[39;49m";

$(document).ready(function () {
	var initialInfo = [
		"--------------------------------------------------",
		"| WebRcon.io Version v1.0.0                      |",
		"| Developed and Maintained by @sekjun9878        |",
		"| For any bugs please contact michael@yoo.id.au  |",
		"--------------------------------------------------",

		"",

		"--------------------------------------------------",
		"| Now you will need to enter your server's       |",
		"| details.                                       |",
		"|                                                |",
		"| Please note that all connection to             |",
		"| our website is secured using HTTPS and that    |",
		"| while your connection is relayed through our   |",
		"| API servers due to javascript limitation,      |",
		"| we do not store your password in any way.      |",
		"|                                                |",
		"| We do however store your server IP (not port)  |",
		"| for rate limiting so that our service doesn't  |",
		"| get used as a brute force reflector.           |",
		"|                                                |",
		"| You may make up to 2 requests per 3 seconds    |",
		"| per client, or 6 requests in 3 seconds to a    |",
		"| specific host. (Any client IPs combined).      |",
		"--------------------------------------------------",

		"",

		"--------------------------------------------------",
		"| While this website runs off ad revenue for     |",
		"| the necessary server costs, donations are very |",
		"| welcome. Any amount is accepted.               |",
		"|                                                |",
		"| Bitcoin: 1JWQ2PMLR491S477vC4hRuQNV9PrbH3kE     |",
		"|                                                |",
		"| That is all. Enjoy!                            |",
		"--------------------------------------------------",

		""
	];

	/*
	 * 0 for white cursor
	 * 1 for green cursor
	 */
	var alternating = 0;

	var term = new Terminal({
		cols: 100,
		rows: calculateRows(window.innerHeight),
		screenKeys: true
	});

	var commandInputLine = $('#term-input');
	var currentTimeIndicator = $('#current-time');
	var termInputPrefix = $("#term-input-prefix-info");
	var termTitle = $("#term-title");

	/*
		0 for uninitialised
		1 for awaiting server address
		2 for awaiting server port
		3 for awaiting server password
		4 for authenticating
		5 for connected
	 */
	var status = 0;

	var address;
	var port;

	var token = "";//RCON password

	term.on("data", function(data) {
		var preLineText = commandInputLine.text();//The text of the input field when this function was called,
		//regardless of its current state

		if (data == "\x7f") {
			commandInputLine.text(preLineText.substr(0, preLineText.length - 1));

			if(status == 3) // Password Input
			{
				token = token.slice(0, - 1);
			}
		} else if (data == "\r") {
			commandInputLine.text("");

			if (preLineText == "//reload")
			{
				term.destroy();
				commandInputLine.text("Reloading...");
				location.reload();
			}

			switch(status)
			{
				case 0: // Uninitialised
					break;
				case 1: // Prompt for address
					ga('send', 'event', 'terminal', 'input', 'server.address');

					$.ajax({
						//TODO:                   < here is a "/" required?
						url: window.location.href + "api.php/validate/address",
						type: 'POST',
						data: toHex(preLineText),
						dataType: "json",
						success: function (body) {
							// If response code 200, then the return result must be valid => true
							if(typeof body == 'object' && body.hasOwnProperty("valid") && body.valid == true)
							{
								//Input server address is valid
								ga('send', 'event', 'terminal', 'validate', 'server.address', 1);

								address = preLineText;
								termInputPrefix.text(" > ");
								term.log("Server IP address has been set to: " + address);
								term.log("");
								status = 2;
								promptServerDetails(1);
							}
							else
							{
								// Malformed JSON request
								term.log(TEXTCOLOUR_RED + "Validation Failed!" + TEXTCOLOUR_RESET);
								term.log(TEXTCOLOUR_RED + "Reason: Malformed JSON response received from server." + TEXTCOLOUR_RESET);
								term.log(TEXTCOLOUR_RED + "This may be due to a problem with the website." + TEXTCOLOUR_RESET);
								term.log(TEXTCOLOUR_RED + "You may either attempt to input again, or if the problem persists," + TEXTCOLOUR_RESET);
								term.log(TEXTCOLOUR_RED + "Please contact michael@yoo.id.au for assistance." + TEXTCOLOUR_RESET);
								term.log("");

								//Reset everything to Enter Server Address
								promptServerDetails(0);
							}
						},
						error: function (xhr, ajaxOptions, thrownError) {
							switch(xhr.status)
							{
								case 400: // Bad Request
									ga('send', 'event', 'terminal', 'validate', 'server.address', 0);

									term.log(TEXTCOLOUR_RED + "Validation Failed!" + TEXTCOLOUR_RESET);
									term.log(TEXTCOLOUR_RED + "Reason: Server Side Validation Failed." + TEXTCOLOUR_RESET);
									term.log(TEXTCOLOUR_RED + "Reason: " + JSON.parse(xhr.responseText).error.message + TEXTCOLOUR_RESET);
									term.log("");

									//Reset everything to Enter Server Address
									promptServerDetails(0);
									break;
								case 429: // Rate Limit
									ga('send', 'event', 'terminal', 'ratelimit', 'server.address');

									term.log(TEXTCOLOUR_RED + "Validation Failed!" + TEXTCOLOUR_RESET);
									term.log(TEXTCOLOUR_RED + "Reason: Rate Limit Exceeded." + TEXTCOLOUR_RESET);
									term.log(TEXTCOLOUR_RED + "Please wait a few seconds before trying again." + TEXTCOLOUR_RESET);
									term.log("");

									//Reset everything to Enter Server Address
									promptServerDetails(0);
									break;
								default:
									term.log(TEXTCOLOUR_RED + "Validation Failed!" + TEXTCOLOUR_RESET);
									term.log(TEXTCOLOUR_RED + "Reason: Unexpected HTTP status code returned by server." + TEXTCOLOUR_RESET);
									term.log(TEXTCOLOUR_RED + "Reason: HTTP/1.1 " + xhr.status + TEXTCOLOUR_RESET);
									term.log(TEXTCOLOUR_RED + "This may be due to a problem with the website." + TEXTCOLOUR_RESET);
									term.log(TEXTCOLOUR_RED + "You may either attempt to input again, or if the problem persists," + TEXTCOLOUR_RESET);
									term.log(TEXTCOLOUR_RED + "Please contact michael@yoo.id.au for assistance." + TEXTCOLOUR_RESET);
									term.log("");

									promptServerDetails(0);
							}
						}
					});
					break;
				case 2: // Prompt for port
					ga('send', 'event', 'terminal', 'input', 'server.port');

					// Check if variable is integer
					// http://stackoverflow.com/questions/14636536/how-to-check-if-a-variable-is-an-integer-in-javascript#comment20448200_14636652
					if(!isNormalInteger(preLineText))
					{
						ga('send', 'event', 'terminal', 'validate', 'server.port', 0);

						term.log(TEXTCOLOUR_RED + "You have entered an invalid port number!" + TEXTCOLOUR_RESET);
						term.log(TEXTCOLOUR_RED + "Validation Error: Port number is not a real integer, or is too large." + TEXTCOLOUR_RESET);
						term.log("");
						promptServerDetails(1);
						break;
					}

					if(parseInt(preLineText, 10) < 0 || parseInt(preLineText, 10) > 65535)
					{
						ga('send', 'event', 'terminal', 'validate', 'server.port', 0);

						term.log(TEXTCOLOUR_RED + "You have entered an invalid port number!" + TEXTCOLOUR_RESET);
						term.log(TEXTCOLOUR_RED + "Validation Error: Outside of range." + TEXTCOLOUR_RESET);
						term.log("");
						promptServerDetails(1);
						break;
					}

					ga('send', 'event', 'terminal', 'validate', 'server.port', 1);

					port = preLineText;
					termInputPrefix.text(" > ");
					term.log("Server port has been set to: "+ port);
					term.log("");
					status = 3;
					promptServerDetails(2);
					break;
				case 3: // Prompt for password
					ga('send', 'event', 'terminal', 'input', 'server.token');

					//token = preLineText; token is already set below - this is done to mask the password
					termInputPrefix.text(" > ");
					term.log("Server password has been set to: ********");
					term.log("");

					termTitle.text("WebRcon.io by @sekjun9878, Version v1.0.0 | Authenticating " + address + ":" + port);
					commandInputLine.text("Authenticating...");
					term.log("Authenticating...");

					status = 4;

					$.ajax({
						//TODO:                   < here is a "/" required?
						url: window.location.href + "api.php/" + toHex(address + ":" + port) + "/authenticate",
						type: 'POST',
						beforeSend: function (xhr) {
							// Set header
							xhr.setRequestHeader("Authorization", "token " + token);
						},
						data: toHex("fakedata"),//TODO: Why?
						dataType: "json",
						success: function (body) {
							if(typeof body == 'object' && body.hasOwnProperty("authenticated") && body.authenticated == true)
							{
								ga('send', 'event', 'terminal', 'authenticate', 'success');

								status = 5;
								term.log(TEXTCOLOUR_GREEN + "Connected!" + TEXTCOLOUR_RESET);
								//termInputPrefix.css("color", "#8ae234");//Cursor colour done in timer tick interval
								termTitle.text("WebRcon.io by @sekjun9878, Version v1.0.0 | Connected " + address + ":" + port);
								commandInputLine.text("");
							}
							else
							{
								// Malformed JSON request
								term.log(TEXTCOLOUR_RED + "Authentication Failed!" + TEXTCOLOUR_RESET);
								term.log(TEXTCOLOUR_RED + "Reason: Malformed JSON response received from server." + TEXTCOLOUR_RESET);
								term.log(TEXTCOLOUR_RED + "This may be due to a problem with the website." + TEXTCOLOUR_RESET);
								term.log(TEXTCOLOUR_RED + "You may either attempt to connect again, or if the problem persists," + TEXTCOLOUR_RESET);
								term.log(TEXTCOLOUR_RED + "Please contact michael@yoo.id.au for assistance." + TEXTCOLOUR_RESET);
								term.log("");

								//Reset everything to before password input
								termTitle.text("WebRcon.io by @sekjun9878, Version v1.0.0 | Not Connected");
								termInputPrefix.text(" > ");
								commandInputLine.text("");
								token = "";
								status = 1;
								promptServerDetails(0);
							}
						},
						error: function (xhr, ajaxOptions, thrownError) {
							switch(xhr.status)
							{
								case 400: // Bad Request
									term.log(TEXTCOLOUR_RED + "Authentication Failed!" + TEXTCOLOUR_RESET);
									term.log(TEXTCOLOUR_RED + "Reason: Server Side Validation Failed." + TEXTCOLOUR_RESET);
									term.log(TEXTCOLOUR_RED + "Reason: " + JSON.parse(xhr.responseText).error.message + TEXTCOLOUR_RESET);
									term.log("");

									//Reset everything to before password input
									termTitle.text("WebRcon.io by @sekjun9878, Version v1.0.0 | Not Connected");
									termInputPrefix.text(" > ");
									commandInputLine.text("");
									token = "";
									status = 1;
									promptServerDetails(0);
									break;
								case 504: // Upstream Time Out
									ga('send', 'event', 'terminal', 'authenticate', 'timeout');

									term.log(TEXTCOLOUR_RED + "Authentication Failed!" + TEXTCOLOUR_RESET);
									term.log(TEXTCOLOUR_RED + "Reason: Connection timed out." + TEXTCOLOUR_RESET);
									term.log("");

									//Reset everything to before password input
									termTitle.text("WebRcon.io by @sekjun9878, Version v1.0.0 | Not Connected");
									termInputPrefix.text(" > ");
									commandInputLine.text("");
									token = "";
									status = 1;
									promptServerDetails(0);
									break;
								case 401: // Unautorized
									ga('send', 'event', 'terminal', 'authenticate', 'unauthorized');

									term.log(TEXTCOLOUR_RED + "Authentication Failed!" + TEXTCOLOUR_RESET);
									term.log(TEXTCOLOUR_RED + "Reason: Incorrect Credentials." + TEXTCOLOUR_RESET);
									term.log("");

									//Reset everything to before password input
									termTitle.text("WebRcon.io by @sekjun9878, Version v1.0.0 | Not Connected");
									termInputPrefix.text(" > ");
									commandInputLine.text("");
									token = "";
									status = 3;
									promptServerDetails(2);
									break;
								case 429: // Rate Limit
									ga('send', 'event', 'terminal', 'ratelimit', 'server.authenticate');

									term.log(TEXTCOLOUR_RED + "Authentication Failed!" + TEXTCOLOUR_RESET);
									term.log(TEXTCOLOUR_RED + "Reason: Rate Limit Exceeded." + TEXTCOLOUR_RESET);
									term.log(TEXTCOLOUR_RED + "Please wait a few seconds before trying again." + TEXTCOLOUR_RESET);
									term.log("");

									//Reset everything to before password input
									termTitle.text("WebRcon.io by @sekjun9878, Version v1.0.0 | Not Connected");
									termInputPrefix.text(" > ");
									commandInputLine.text("");
									token = "";
									status = 3;
									promptServerDetails(2);
									break;
								default:
									term.log(TEXTCOLOUR_RED + "Authentication Failed!" + TEXTCOLOUR_RESET);
									term.log(TEXTCOLOUR_RED + "Reason: Unexpected HTTP status code returned by server." + TEXTCOLOUR_RESET);
									term.log(TEXTCOLOUR_RED + "Reason: HTTP/1.1 " + xhr.status + TEXTCOLOUR_RESET);
									term.log(TEXTCOLOUR_RED + "This may be due to a problem with the website." + TEXTCOLOUR_RESET);
									term.log(TEXTCOLOUR_RED + "You may either attempt to connect again, or if the problem persists," + TEXTCOLOUR_RESET);
									term.log(TEXTCOLOUR_RED + "Please contact michael@yoo.id.au for assistance." + TEXTCOLOUR_RESET);
									term.log("");

									//Reset everything to before password input
									termTitle.text("WebRcon.io by @sekjun9878, Version v1.0.0 | Not Connected");
									termInputPrefix.text(" > ");
									commandInputLine.text("");
									token = "";
									status = 1;
									promptServerDetails(0);
							}
						}
					});
					break;
				case 4:
					commandInputLine.text("Authenticating...");//On enter, Reset text to
					break;//Ignore input
				case 5: // Active Connection
					ga('send', 'event', 'terminal', 'input', 'command');

					term.log(preLineText/* + data*/);//Exclude Newline (data would be newline)

					//Send RCON Command

					$.ajax({
						//TODO:                   < here is a "/" required?
						url: window.location.href + "api.php/" + toHex(address + ":" + port) + "/rcon",
						type: 'POST',
						beforeSend: function (xhr) {
							// Set header
							xhr.setRequestHeader("Authorization", "token " + token);
						},
						data: toHex(preLineText),
						dataType: "json",
						success: function (body) {
							var response = body.response;
							$.each(response, function (key, value) {
								term.log(value);
							});
						}
					});
					break;
				default:
			}
		} else {
			if(status == 3) // Password Input
			{
				token += data;
				data = "*";
			}

			if(status != 4) // Don't allow input when status is Authenticating
			{
				commandInputLine.text(preLineText + data);
			}
		}
	});


	term.on("title", function(title) {
		termTitle.text(title);
	});

	var parent_element = document.getElementById("container-terminal");

	term.open(parent_element);

	term.log = function (message) {
		var date = new Date();

		term.write("\x1b[36;1m" +
		(date.getHours()<10?'0':'') + date.getHours() + //Always display two digits, prepending 0 on single digits
		":" + (date.getMinutes()<10?'0':'') + date.getMinutes() +
		":" + (date.getSeconds()<10?'0':'') + date.getSeconds() +
		"\x1b[39;49m" +
		" " + message + "\r\n");
	};

	function initialiseTerm()
	{
		status = 1;//Should've been done in setInterval but just in case
		termTitle.text("WebRcon.io by @sekjun9878, Version v1.0.0 | Not Connected");

		term.write("\r\n");

		commandInputLine.text("");

		var x = setInterval(function () {
			term.log(initialInfo.shift());

			if(initialInfo.length == 0)
			{
				clearInterval(x);
				promptServerDetails(0);
			}
		}, 5);
	}

	function promptServerDetails(message)
	{
		switch(message)
		{
			case 0:
				term.log("Please enter the server IP address:");
				termInputPrefix.text(" Server IP Address > ");
				break;
			case 1:
				term.log("Please enter the server port:");
				termInputPrefix.text(" Server Port > ");
				break;
			case 2:
				term.log("Please enter the server RCON password:");
				termInputPrefix.text(" Server RCON Password > ");
				break;
			default:
		}
	}

	var prevSec = false;

	setInterval(function () {
		var date = new Date();

		var seconds = date.getSeconds();

		if(prevSec == false)
		{
			prevSec = seconds;
		}

		currentTimeIndicator.text((date.getHours()<10?'0':'') + date.getHours() + //Always display two digits, prepending 0 on single digits
			":" + (date.getMinutes()<10?'0':'') + date.getMinutes() +
			":" + (seconds<10?'0':'') + seconds);

		if(status == 0)
		{
			status = 1;
			initialiseTerm();
		}

		if(status == 5 && prevSec !== seconds) // If connected alternate cursor colour
		{
			if(alternating == 0) // White
			{
				alternating = 1;
				termInputPrefix.css("color", "#8ae234");//Change cursor colour to green
			}
			else
			{
				alternating = 0;
				termInputPrefix.css("color", "#f0f0f0");//Change cursor colour to white
			}

			prevSec = seconds;
		}
	}, 200);
});

function toHex(str) {
	var hex = '';
	for(var i=0;i<str.length;i++) {
		hex += ''+str.charCodeAt(i).toString(16);
	}
	return hex;
}

// Is string positive integer including 0
// http://stackoverflow.com/a/10834843
function isNormalInteger(str) {
	var n = ~~Number(str);
	return String(n) === str && n >= 0;
}

function calculateRows(size)
{
	var preSizes = {
		768: 39,
		1099: 56,
		1105: 59,
		640: 32
	};

	if(size in preSizes)
	{
		return preSizes[size];
	}

	var a = 0.05531087;
	var b = -3.4554702;

	return Math.round(a*size+ b) - 1;
}