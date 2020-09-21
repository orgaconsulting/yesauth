<?php

namespace Drupal\yesauth\Controller;


use Drupal\Component\Utility\Crypt;
use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Routing\TrustedRedirectResponse;
use Drupal\Core\Url;
use Drupal\yesauth\Event\YesAuthEvent;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Psr\Http\Message\ResponseInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

/**
 * Class YesController.
 *
 * Does all the magic for the yes identity flow, see
 * https://yes.com/docs/rp-devguide/1.2/index.html
 *
 */
class YesController extends ControllerBase {

  // my site's yes configuration
  protected $config;

  /**
   * GuzzleHttp\ClientInterface definition.
   *
   * @var \GuzzleHttp\ClientInterface
   */
  protected $httpClient;

  /**
   * Drupal\Core\Logger\LoggerChannelFactoryInterface definition.
   *
   * @var \Drupal\Core\Logger\LoggerChannelFactoryInterface
   */
  protected $loggerFactory;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    $instance = parent::create($container);
    $instance->httpClient = $container->get('http_client');
    $instance->loggerFactory = $container->get('logger.factory');

    // get config
    $instance->config = \Drupal::config('yesauth.yesauthconfig');

    return $instance;
  }



  /**
   * Get tokens
   *
   * @param string $authorization_code
   *   A authorization code string.
   *
   * @return array|bool
   *   A result array or false.
   */
  protected function retrieveTokens($authorization_code) {
    // Exchange `code` for access token and ID token.
    $redirect_uri = $this->config->get('redirect_uri');
    $tempstore = \Drupal::service('tempstore.private')->get('yesauth');
    $endpoint = $tempstore->get('token_endpoint');

    $request_options = [
      'form_params' => [
        'code' => $authorization_code,
        'client_id' => $this->config->get('client_id'),
        'redirect_uri' => $redirect_uri,
        'grant_type' => 'authorization_code',
      ],
      'headers' => [
        'Accept' => 'application/json',
      ],
      'cert' => $this->config->get('pem_client_cert_path'),
      'ssl_key' => $this->config->get('pem_cert_key'),
    ];

    $client = $this->httpClient;
    try {
      $response = $client->post($endpoint, $request_options);
      $response_data = json_decode((string) $response->getBody(), TRUE);

      // Expected result.
      $tokens = [
        'id_token' => isset($response_data['id_token']) ? $response_data['id_token'] : NULL,
        'access_token' => isset($response_data['access_token']) ? $response_data['access_token'] : NULL,
      ];
      if (array_key_exists('expires_in', $response_data)) {
        $tokens['expire'] = \Drupal::time()->getRequestTime() + $response_data['expires_in'];
      }
      if (array_key_exists('refresh_token', $response_data)) {
        $tokens['refresh_token'] = $response_data['refresh_token'];
      }
      return $tokens;
    }
    catch (\Exception $e) {
      $variables = [
        '@message' => 'Could not retrieve tokens',
        '@error_message' => $e->getMessage(),
      ];
      $this->loggerFactory->get('yesauth')
        ->error('@message. Details: @error_message', $variables);
      return FALSE;
    }
  }

  /**
   * Fetch json web keyset from idp
   *
   * @return array
   *
   * @throws \Exception
   */
  protected function fetchJWKSKeys() {
    $tempstore = \Drupal::service('tempstore.private')->get('yesauth');
    $jwks_uri = $tempstore->get('jwks_uri');
    if (empty($jwks_uri)) {
      throw new AccessDeniedHttpException('No JWKS URI found');
    }

    /** @var ResponseInterface $response */
    $response = $this->httpClient->get($jwks_uri,
      [
        'headers' => [
          'Accept' => 'application/json',
          'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0'
        ]
      ]);
    $jwksdata = (string) $response->getBody();
    $code = $response->getStatusCode();
    if ($code != 200) {
      throw new NotFoundHttpException("No JWKS ok(200) response, got $code");
    }

    $jwks = (array) json_decode($jwksdata, TRUE);
    $keys = JWK::parseKeySet($jwks);

    return $keys;
  }

  /**
   * Provide redirection to the bank selection for the "yes button"
   * https://yes.com/docs/rp-devguide/1.2/index.html#_starting_point_the_yes_button
   *
   * @return \Drupal\Core\Routing\TrustedRedirectResponse
   */
  public function start() {
    // build accchooser
    $cid = $this->config->get('client_id');
    $url = $this->config->get('yes_uri');
    $url = $url.'/?client_id='.$cid;
    //  check "select another bank"
    $tempstore = \Drupal::service('tempstore.private')->get('yesauth');
    $select_account = $tempstore->get('select_account');
    if (!empty($select_account)) {
      /*
       * https://yes.com/docs/rp-devguide/1.2/index.html
       * The prompt parameter MUST only be used if your app receives an OpenID Connect Authorization Response with error code account_selection_requested
       */
      $url = $url.'&prompt=select_account';
    }
    return new TrustedRedirectResponse($url, 302);
  }

  /**
   * YES Authentication Response Handler
   * https://yes.com/docs/rp-devguide/1.2/IDENTITY/index.html#_authentication_response
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *
   */
  public function login(Request $request) {
    $tempstore = \Drupal::service('tempstore.private')->get('yesauth');
    $idp_code = $request->get('code');
    $idp_state = $request->get('state');
    $idp_iss = $request->get('iss');
    $error = $request->get('error');
    if (!empty($error)) {
      if ("account_selection_requested" == $error) {
        $tempstore->set('select_account', "1");
        return $this->redirect("yesauth.start");
      }
      \Drupal::messenger()->addError("Sorry, das hat leider nicht geklappt - ein admin wird sich die logs ansehen.");
      $this->loggerFactory->get('yesauth')
        ->error('Login() got error from yes.com. Details: @error_message', ['@error_message' => $error]);
      return $this->redirect('<front>');
    }

    $state = $tempstore->get('state');
    $nonce = $tempstore->get('nonce');
    $iss = $tempstore->get('iss');
    // The state in session value must now be invalidated
    $tempstore->set('state', '');
    $tempstore->set('nonce', '');
    $tempstore->set('select_account', '');

    // request token
    $tokens = $this->retrieveTokens($idp_code);
    if (!is_array($tokens)) {
      throw new AccessDeniedHttpException("got no yesl tokens");
    }

    // fetch jwks keys
    try {
      $keys = $this->fetchJWKSKeys();
    } catch (\Exception $e) {
      $variables = [
        '@message' => 'No good JWKS response',
        '@error_message' => $e->getMessage(),
      ];
      $this->loggerFactory->get('yesauth')
        ->error('@message. Details: @error_message', $variables);
      throw new AccessDeniedHttpException('No JWKS response');
    }

    $id_token = $tokens['id_token'];
    $decoded = JWT::decode($id_token, $keys, ['ES256', 'HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512']);

    // checks
    if (empty($decoded->sub)) {
      throw new AccessDeniedHttpException("No sub elem in id_token");
    }
    if ((empty($decoded->aud)) || ($decoded->aud != $this->config->get('client_id'))) {
      throw new AccessDeniedHttpException("No or wrong aud elem in id_token");
    }
    if ((empty($decoded->exp)) || ($decoded->exp < time())) {
      throw new AccessDeniedHttpException("No or wrong exp elem in id_token");
    }
    if ((empty($decoded->nonce)) || ($decoded->nonce != $nonce)) {
      throw new AccessDeniedHttpException("No or wrong nonce elem in id_token");
    }
    if ((empty($decoded->iss)) || ($decoded->iss != $iss)) {
      throw new AccessDeniedHttpException("No or wrong iss elem in id_token");
    }
    if ((empty($idp_state)) || ($idp_state != $state)) {
      // check again against server session store
      throw new AccessDeniedHttpException("No or wrong state elem in resp/session");
    }
    if ((empty($idp_iss)) || ($idp_iss != $iss)) {
      // You app MUST check that this value is equal to the issuer URL used in the previous steps. This is a countermeasure against mix-up attacks.
      throw new AccessDeniedHttpException("No or wrong iss elem in id_token");
    }

    // fire event to inform subscribers
    $event = new YesAuthEvent((array)$decoded, $this->currentUser());
    $event_dispatcher = \Drupal::service('event_dispatcher');
    $event_dispatcher->dispatch(YesAuthEvent::YESAUTH_AUTH_EVENT, $event);

    // log flow
    $variables = [
      '@message' => 'Successful yes.com flow',
      '@uid' => $this->currentUser->isAnonymous() ? '[anon]' : $this->currentUser->id(),
    ];
    $this->loggerFactory->get('yesauth')
      ->info('@message. User: @uid', $variables);

    // redir to like configured routes
    if ($this->currentUser->isAnonymous()) {
      $target = $this->config->get('anon_dest');
    } else {
      $target = $this->config->get('auth_dest');
    }
    if ("<front>" == $target) {
      $target = "/";
    }

    return new TrustedRedirectResponse($target, 302);
  }

  /**
   * IDP Auth.
   * Gets called by the AccChosser
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *
   * https://yes.com/docs/rp-devguide/1.2/index.html#autherrorresponse
   * After your user selected her bank, the account chooser will redirect her, using HTTP status code 302, to your 📦 Account Chooser Redirect URI.
   *
   */
  public function auth(Request $request) {

    // the OpenID Connect Issuer URL of the selected OP
    $issuer_url = $request->get('issuer_url');
    // we don't use "state" currently here in ac_chooser
    $state = $request->get('state');

    $error = $request->get('error');
    // https://yes.com/docs/rp-devguide/1.2/index.html#_yes_account_chooser_error_response
    if (!empty($error)) {
      if ($error == 'canceled') {
        \Drupal::messenger()->addMessage("Schade, Du hast den Flow abgebrochen.");
        return $this->redirect('<front>');
      } else {
        \Drupal::messenger()->addError("Sorry, das klappt leider nicht - ein admin wird sich die logs ansehen.");
        $this->loggerFactory->get('yesauth')
          ->error('Auth() got error from yes.com. Details: @error_message', ['@error_message' => $error]);
        return $this->redirect('<front>');
      }
    }

    // make iss check (https://yes.com/docs/rp-devguide/1.2/IDENTITY/index.html#_issuer_uri_check)
    $client = $this->httpClient;
    $issreq = $this->config->get('yes_uri')."/idp/?iss=".urlencode($issuer_url);
    try {
      /** @var ResponseInterface $response */
      $response = $client->get($issreq);
      $code = $response->getStatusCode();
      if ($code != 204) {
        \Drupal::messenger()->addError("Mit dieser Bank ist eine Autorisierung aktuell nicht möglich");
        // MAYBE: redir to something with more sense fro the user
        return $this->redirect('<front>');
      }
    }
    catch (\Exception $e) {
      $variables = [
        '@message' => 'ISS check faild',
        '@error_message' => $e->getMessage(),
      ];
      $this->loggerFactory->get('yesauth')
        ->error('@message. Details: @error_message', $variables);
      throw new AccessDeniedHttpException('ISS failure');
    }

    // get idp config
    // https://yes.com/docs/rp-devguide/1.2/IDENTITY/index.html#discovery
    $issreq = "{$issuer_url}/.well-known/openid-configuration";
    try {
      /** @var ResponseInterface $response */
      $response = $client->get($issreq,
        [
          'headers' => [
            'Accept' => 'application/json',
            'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0'
          ]
        ]);
      $idpdata = (string) $response->getBody();
      $code = $response->getStatusCode();
      if ($code != 200) {
        \Drupal::messenger()->addError("Mit dieser Bank ist eine Autorisierung gerade nicht möglich");
        return $this->redirect('<front>');
      }
    }
    catch (\Exception $e) {
      $variables = [
        '@message' => 'ISS/.well-known check faild',
        '@error_message' => $e->getMessage(),
      ];
      $this->loggerFactory->get('yesauth')
        ->error('@message. Details: @error_message', $variables);
      // TODO: think if accessdenied is ok
      throw new AccessDeniedHttpException('ISS/.well-known request failure');
    }

    $oidcData = json_decode($idpdata);
    // check iss
    if ($oidcData->issuer != $issuer_url) {
      $variables = [
        '@message' => 'ISS issuer_url check faild',
      ];
      $this->loggerFactory->get('yesauth')
        ->error('@message.', $variables);
      // think if accessdenied is ok here
      throw new AccessDeniedHttpException('ISS issuer_url request failure');
    }

    // add claims from config
    $tdt_claims = $this->config->get('tdt_claims');
    $claimsArray = explode(',', $tdt_claims);
    $claimsArrayKeys = [];
    foreach ($claimsArray as $ca) { $claimsArrayKeys[trim($ca)] = null; }
    $claims = [
      "id_token" => (object)$claimsArrayKeys,
    ];

    // create random state and nounce
    $ys = Crypt::randomBytesBase64();
    $yn = Crypt::randomBytesBase64();

    // https://api.drupal.org/api/drupal/core%21lib%21Drupal%21Core%21TempStore%21PrivateTempStore.php/class/PrivateTempStore/8.7.x
    // A PrivateTempStore can be used to make temporary, non-cache data available across requests.
    $tempstore = \Drupal::service('tempstore.private')->get('yesauth');
    $tempstore->set('token_endpoint', $oidcData->token_endpoint);
    $tempstore->set('jwks_uri', $oidcData->jwks_uri);
    $tempstore->set('state', $ys);
    $tempstore->set('nonce', $yn);
    $tempstore->set('iss', $issuer_url);

    // finally redir the user to the authorization_endpoint
    // https://yes.com/docs/rp-devguide/1.2/IDENTITY/index.html#authentication_request
    $url_options = [
      'query' => [
        'client_id' => $this->config->get('client_id'),
        'response_type' => 'code',
        'scope' => 'openid',
        'claims' => json_encode($claims),
        'redirect_uri' => $this->config->get('redirect_uri'),
        'state' => $ys,
        'nonce' => $yn,
      ],
    ];
    $authUrl = Url::fromUri($oidcData->authorization_endpoint, $url_options);

    return new TrustedRedirectResponse($authUrl->toString(), 302);

  }

}
