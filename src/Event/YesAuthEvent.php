<?php

namespace Drupal\yesauth\Event;

use Drupal\Core\Session\AccountInterface;
use Symfony\Component\EventDispatcher\Event;

/**
 * Event that is fired when a yes auth event occurs
 */
class YesAuthEvent extends Event {

  const YESAUTH_AUTH_EVENT = 'yesauth.authevent';

  /**
   * The account.
   *
   * @var AccountInterface
   */
  public $account;

  /**
   * @var array
   */
  public $claimsData;

  /**
   * Constructs the object.
   *
   * @param array $claimsData
   *    Claims data provided by yes.com for the requested claims
   *
   * @param AccountInterface $account
   *   The account of the user logged in.
   */
  public function __construct(array $claimsData, AccountInterface $account = null) {
    $this->account = $account;
    $this->claimsData = $claimsData;
  }

  /**
   * @return AccountInterface
   */
  public function getAccount(): AccountInterface {
    return $this->account;
  }

  /**
   * @return array
   */
  public function getClaimsData(): array {
    return $this->claimsData;
  }


}
