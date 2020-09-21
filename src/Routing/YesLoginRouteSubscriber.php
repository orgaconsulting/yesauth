<?php

namespace Drupal\yesauth\Routing;

use Drupal\Core\Routing\RouteSubscriberBase;
use Drupal\Core\Url;
use GuzzleHttp\Psr7\Uri;
use Symfony\Component\Routing\RouteCollection;

/**
 * Class YesLoginRouteSubscriber.
 *
 * Listens to the dynamic route events.
 */
class YesLoginRouteSubscriber extends RouteSubscriberBase {

  /**
   * {@inheritdoc}
   */
  protected function alterRoutes(RouteCollection $collection) {
    /* @var \Symfony\Component\Routing\Route $route */
    if ($route = $collection->get('yesauth.login')) {
      $config = \Drupal::config('yesauth.yesauthconfig');
      $uri = new Uri($config->get('redirect_uri'));
      $route->setPath($uri->getPath());
    }
    if ($route = $collection->get('yesauth.auth')) {
      $config = \Drupal::config('yesauth.yesauthconfig');
      $uri = new Uri($config->get('yes_ac_uri'));
      $route->setPath($uri->getPath());
    }
  }
}
