<?php

namespace Drupal\yesauth\Tests;

use Drupal\simpletest\WebTestBase;
use GuzzleHttp\ClientInterface;
use Drupal\Core\Logger\LoggerChannelFactoryInterface;

/**
 * Provides automated tests for the yesauth module.
 */
class YesControllerTest extends WebTestBase {

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
  public static function getInfo() {
    return [
      'name' => "yesauth YesController's controller functionality",
      'description' => 'Test Unit for module yesauth and controller YesController.',
      'group' => 'Other',
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function setUp() {
    parent::setUp();
  }

  /**
   * Tests yesauth functionality.
   */
  public function testYesController() {
    // Check that the basic functions of module yesauth.
    $this->assertEquals(TRUE, TRUE, 'Test Unit Generated via Drupal Console.');
  }

}
