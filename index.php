<?php
ini_set('display_errors', 1);

class AccessTokenAuthentication {
    /*
     * Get the access token.
     *
     * @param string $grantType    Grant type.
     * @param string $scopeUrl     Application Scope URL.
     * @param string $clientID     Application client ID.
     * @param string $clientSecret Application client ID.
     * @param string $authUrl      Oauth Url.
     *
     * @return string.
     */
    function getTokens($grantType, $scopeUrl, $clientID, $clientSecret, $authUrl){
        try {
            //Initialize the Curl Session.
            $ch = curl_init();
            //Create the request Array.
            $paramArr = array (
                 'grant_type'    => $grantType,
                 'scope'         => $scopeUrl,
                 'client_id'     => $clientID,
                 'client_secret' => $clientSecret
            );
            //Create an Http Query.//
            $paramArr = http_build_query($paramArr);
            //Set the Curl URL.
            curl_setopt($ch, CURLOPT_URL, $authUrl);
            //Set HTTP POST Request.
            curl_setopt($ch, CURLOPT_POST, TRUE);
            //Set data to POST in HTTP "POST" Operation.
            curl_setopt($ch, CURLOPT_POSTFIELDS, $paramArr);
            //CURLOPT_RETURNTRANSFER- TRUE to return the transfer as a string of the return value of curl_exec().
            curl_setopt ($ch, CURLOPT_RETURNTRANSFER, TRUE);
            //CURLOPT_SSL_VERIFYPEER- Set FALSE to stop cURL from verifying the peer's certificate.
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            //Execute the  cURL session.
            $strResponse = curl_exec($ch);
            //Get the Error Code returned by Curl.
            $curlErrno = curl_errno($ch);
            if($curlErrno){
                $curlError = curl_error($ch);
                throw new Exception($curlError);
            }
            //Close the Curl Session.
            curl_close($ch);
            //Decode the returned JSON string.
            $objResponse = json_decode($strResponse);
            if (isset($objResponse->error)){
                throw new Exception($objResponse->error_description);
            }
            return $objResponse->access_token;
        } catch (Exception $e) {
            echo "Exception-".$e->getMessage();
        }
    }
}

/*
 * Class:HTTPTranslator
 *
 * Processing the translator request.
 */
Class HTTPTranslator {
    /*
     * Create and execute the HTTP CURL request.
     *
     * @param string $url        HTTP Url.
     * @param string $authHeader Authorization Header string.
     *
     * @return string.
     *
     */
    function curlRequest($url, $authHeader) {
        //Initialize the Curl Session.
        $ch = curl_init();
        //Set the Curl url.
        curl_setopt ($ch, CURLOPT_URL, $url);
        //Set the HTTP HEADER Fields.
        curl_setopt ($ch, CURLOPT_HTTPHEADER, array($authHeader,"Content-Type: text/xml", 'Content-Length: 0'));
        //CURLOPT_RETURNTRANSFER- TRUE to return the transfer as a string of the return value of curl_exec().
        curl_setopt ($ch, CURLOPT_RETURNTRANSFER, TRUE);
        //CURLOPT_SSL_VERIFYPEER- Set FALSE to stop cURL from verifying the peer's certificate.
        curl_setopt ($ch, CURLOPT_SSL_VERIFYPEER, False);
        //Set HTTP POST Request.
        curl_setopt($ch, CURLOPT_POST, TRUE);
        //Execute the  cURL session.
        $curlResponse = curl_exec($ch);
        //Get the Error Code returned by Curl.
        $curlErrno = curl_errno($ch);
        if ($curlErrno) {
            $curlError = curl_error($ch);
            throw new Exception($curlError);
        }
        //Close a cURL session.
        curl_close($ch);
        return $curlResponse;
    }
}


/*
 * Class:TwitterAPIExchange
 *
 * Class found from internet for handling Twitter requests
 */
class TwitterAPIExchange
{
    private $oauth_access_token;
    private $oauth_access_token_secret;
    private $consumer_key;
    private $consumer_secret;
    private $postfields;
    private $getfield;
    protected $oauth;
    public $url;

    /**
     * Create the API access object. Requires an array of settings::
     * oauth access token, oauth access token secret, consumer key, consumer secret
     * These are all available by creating your own application on dev.twitter.com
     * Requires the cURL library
     * 
     * @param array $settings
     */
    public function __construct(array $settings)
    {
        if (!in_array('curl', get_loaded_extensions())) 
        {
            throw new Exception('You need to install cURL');
        }
        
        if (!isset($settings['oauth_access_token'])
            || !isset($settings['oauth_access_token_secret'])
            || !isset($settings['consumer_key'])
            || !isset($settings['consumer_secret']))
        {
            throw new Exception('Make sure you are passing in the correct parameters');
        }

        $this->oauth_access_token = $settings['oauth_access_token'];
        $this->oauth_access_token_secret = $settings['oauth_access_token_secret'];
        $this->consumer_key = $settings['consumer_key'];
        $this->consumer_secret = $settings['consumer_secret'];
    }
    
    /**
     * Set postfields array, example: array('screen_name' => 'J7mbo')
     * 
     * @param array $array Array of parameters to send to API
     * 
     * @return TwitterAPIExchange Instance of self for method chaining
     */
    public function setPostfields(array $array)
    {
        if (!is_null($this->getGetfield())) 
        { 
            throw new Exception('You can only choose get OR post fields.'); 
        }
        
        if (isset($array['status']) && substr($array['status'], 0, 1) === '@')
        {
            $array['status'] = sprintf("\0%s", $array['status']);
        }
        
        $this->postfields = $array;
        
        return $this;
    }
    
    /**
     * Set getfield string, example: '?screen_name=J7mbo'
     * 
     * @param string $string Get key and value pairs as string
     * 
     * @return \TwitterAPIExchange Instance of self for method chaining
     */
    public function setGetfield($string)
    {
        if (!is_null($this->getPostfields())) 
        { 
            throw new Exception('You can only choose get OR post fields.'); 
        }
        
        $search = array('#', ',', '+', ':');
        $replace = array('%23', '%2C', '%2B', '%3A');
        $string = str_replace($search, $replace, $string);  
        
        $this->getfield = $string;
        
        return $this;
    }
    
    /**
     * Get getfield string (simple getter)
     * 
     * @return string $this->getfields
     */
    public function getGetfield()
    {
        return $this->getfield;
    }
    
    /**
     * Get postfields array (simple getter)
     * 
     * @return array $this->postfields
     */
    public function getPostfields()
    {
        return $this->postfields;
    }
    
    /**
     * Build the Oauth object using params set in construct and additionals
     * passed to this method. For v1.1, see: https://dev.twitter.com/docs/api/1.1
     * 
     * @param string $url The API url to use. Example: https://api.twitter.com/1.1/search/tweets.json
     * @param string $requestMethod Either POST or GET
     * @return \TwitterAPIExchange Instance of self for method chaining
     */
    public function buildOauth($url, $requestMethod)
    {
        if (!in_array(strtolower($requestMethod), array('post', 'get')))
        {
            throw new Exception('Request method must be either POST or GET');
        }
        
        $consumer_key = $this->consumer_key;
        $consumer_secret = $this->consumer_secret;
        $oauth_access_token = $this->oauth_access_token;
        $oauth_access_token_secret = $this->oauth_access_token_secret;
        
        $oauth = array( 
            'oauth_consumer_key' => $consumer_key,
            'oauth_nonce' => time(),
            'oauth_signature_method' => 'HMAC-SHA1',
            'oauth_token' => $oauth_access_token,
            'oauth_timestamp' => time(),
            'oauth_version' => '1.0'
        );
        
        $getfield = $this->getGetfield();
        
        if (!is_null($getfield))
        {
            $getfields = str_replace('?', '', explode('&', $getfield));
            foreach ($getfields as $g)
            {
                $split = explode('=', $g);
                $oauth[$split[0]] = $split[1];
            }
        }
        
        $base_info = $this->buildBaseString($url, $requestMethod, $oauth);
        $composite_key = rawurlencode($consumer_secret) . '&' . rawurlencode($oauth_access_token_secret);
        $oauth_signature = base64_encode(hash_hmac('sha1', $base_info, $composite_key, true));
        $oauth['oauth_signature'] = $oauth_signature;
        
        $this->url = $url;
        $this->oauth = $oauth;
        
        return $this;
    }
    
    /**
     * Perform the actual data retrieval from the API
     * 
     * @param boolean $return If true, returns data.
     * 
     * @return string json If $return param is true, returns json data.
     */
    public function performRequest($return = true)
    {
        if (!is_bool($return)) 
        { 
            throw new Exception('performRequest parameter must be true or false'); 
        }
        
        $header = array($this->buildAuthorizationHeader($this->oauth), 'Expect:');
        
        $getfield = $this->getGetfield();
        $postfields = $this->getPostfields();

        $options = array( 
            CURLOPT_HTTPHEADER => $header,
            CURLOPT_HEADER => false,
            CURLOPT_URL => $this->url,
            CURLOPT_RETURNTRANSFER => true,
  		CURLOPT_SSL_VERIFYPEER => false
        );

        if (!is_null($postfields))
        {
            $options[CURLOPT_POSTFIELDS] = $postfields;
        }
        else
        {
            if ($getfield !== '')
            {
                $options[CURLOPT_URL] .= $getfield;
            }
        }

        $feed = curl_init();
        curl_setopt_array($feed, $options);
        $json = curl_exec($feed);
		//echo curl_error($feed);
        curl_close($feed);

        if ($return) { return $json; }
    }
    
    /**
     * Private method to generate the base string used by cURL
     * 
     * @param string $baseURI
     * @param string $method
     * @param array $params
     * 
     * @return string Built base string
     */
    private function buildBaseString($baseURI, $method, $params) 
    {
        $return = array();
        ksort($params);
        
        foreach($params as $key=>$value)
        {
            $return[] = "$key=" . $value;
        }
        
        return $method . "&" . rawurlencode($baseURI) . '&' . rawurlencode(implode('&', $return)); 
    }
    
    /**
     * Private method to generate authorization header used by cURL
     * 
     * @param array $oauth Array of oauth data generated by buildOauth()
     * 
     * @return string $return Header used by cURL for request
     */    
    private function buildAuthorizationHeader($oauth) 
    {
        $return = 'Authorization: OAuth ';
        $values = array();
        
        foreach($oauth as $key => $value)
        {
            $values[] = "$key=\"" . rawurlencode($value) . "\"";
        }
        
        $return .= implode(', ', $values);
        return $return;
    }

}

?>
<html>
<head>
<script src="http://ajax.googleapis.com/ajax/libs/jquery/1.10.2/jquery.min.js"></script>
<script type="text/javascript">
$(document).ready(function(){
	$("#handleToTransalate").hide();
  $(".radio_buttons").click(function(){
    val = $(this).val();
	if(val=="Text") {
		$("#textToTransalate").show();
		$("#handleToTransalate").hide();
		$("#handleToTransalate").val('');
		
	}
	else {
		$("#handleToTransalate").show();
		$("#textToTransalate").hide();
		$("#textToTransalate").val('');
	}
  });
}); 
</script>
</head>
<body>
<input type="radio" name="translate" id="translate" class="radio_buttons" value="Text" checked="checked" />Text <input type="radio" name="translate" id="translate" class="radio_buttons" value="Twitter" />Twitter Handle
<form name="translateform" method="post" action="index.php">
<textarea name="textToTransalate" id="textToTransalate" ></textarea>
<input type="text" name="handleToTransalate" id="handleToTransalate" />
<input type="submit" name="submitforTranslation" value="Translate" />
</form>
<div id="results">
<?php
if(isset($_POST['textToTransalate']) && $_POST['textToTransalate']!="") {
	$texts[] = $_POST['textToTransalate'];
}
if(isset($_POST['handleToTransalate']) && $_POST['handleToTransalate']!="") {
	$handle = $_POST['handleToTransalate'];
	$settings = array(
			'oauth_access_token' => "87629878-siZJ63sYZWHcX7OW3b7nuaZ9HFre4vtvn6svPH0Nv",
			'oauth_access_token_secret' => "cLUvaPN99JDMiTm7hFfddRUrGEntlx3VTUGDbiFE",
			'consumer_key' => "2ljRKJt0GE1DD0sno9Vg",
			'consumer_secret' => "oLftoxPUJoXW9cZ3wyvYxicOMdxJXZGXasaecEOlxY"
	);
	$url = 'https://api.twitter.com/1.1/search/tweets.json';
	$getfield = '?q=' . $handle . '&count=5';
	$requestMethod = 'GET';
	$twitter = new TwitterAPIExchange($settings);
	$output = json_decode($twitter->setGetfield($getfield)
			->buildOauth($url, $requestMethod)
			->performRequest());
	foreach($output->statuses as $tweet) {
		$texts[] = $tweet->text . "<br/>";
	}
	
}
if(isset($texts)) {
	foreach($texts as $text) {
		if($text!="") {
			try {
				//Client ID of the application.
				$clientID       = "ASDFhjkl";
				//Client Secret key of the application.
				$clientSecret = "FCMw4pA9zatFSyp462FJsS6KMsEfRma4G3UygR7EnQM=";
				//OAuth Url.
				$authUrl      = "https://datamarket.accesscontrol.windows.net/v2/OAuth2-13/";
				//Application Scope Url
				$scopeUrl     = "http://api.microsofttranslator.com";
				//Application grant type
				$grantType    = "client_credentials";
			
				//Create the AccessTokenAuthentication object.
				$authObj      = new AccessTokenAuthentication();
				//Get the Access token.
				$accessToken  = $authObj->getTokens($grantType, $scopeUrl, $clientID, $clientSecret, $authUrl);
				//Create the authorization Header string.
				$authHeader = "Authorization: Bearer ". $accessToken;
			
			
				//Set the Params.
				$inputStr        = $text;
				$fromLanguage   = "en";
				$toLanguage        = "de";
				$user            = 'Test';
				$category       = "general";
				$uri             = null;
				$contentType    = "text/plain";
				$maxTranslation = 5;
			
				//Create the string for passing the values through GET method.
				$params = "from=$fromLanguage".
							"&to=$toLanguage".
							"&maxTranslations=$maxTranslation".
							"&text=".urlencode($inputStr).
							"&user=$user".
							"&uri=$uri".
							"&contentType=$contentType";
			
				//HTTP getTranslationsMethod URL.
				$getTranslationUrl = "http://api.microsofttranslator.com/V2/Http.svc/GetTranslations?$params";
			
				//Create the Translator Object.
				$translatorObj = new HTTPTranslator();
			
				//Call the curlRequest.
				$curlResponse = $translatorObj->curlRequest($getTranslationUrl, $authHeader);
				//Interprets a string of XML into an object.
				$xmlObj = simplexml_load_string($curlResponse);
				$translationObj = $xmlObj->Translations;
				$translationMatchArr = $translationObj->TranslationMatch;
				echo "Get Translation For <b>$inputStr</b>";
				echo "<table border ='2px' cellpadding='2' cellspacing='0'>";
				echo "<tr><td><b>Count</b></td><td><b>MatchDegree</b></td>
					<td><b>Rating</b></td><td><b>TranslatedText</b></td></tr>";
				foreach($translationMatchArr as $translationMatch) {
					echo "<tr><td>$translationMatch->Count</td><td>$translationMatch->MatchDegree</td><td>$translationMatch->Rating</td>
						<td>$translationMatch->TranslatedText</td></tr>";
				}
				echo "</table></br>";
			} 
			catch (Exception $e) {
				echo "Exception: " . $e->getMessage() . PHP_EOL;
			}
		}
	}
}
?>
</div>
</body>
</html>
