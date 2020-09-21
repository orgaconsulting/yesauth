<?php

namespace Drupal\yesauth\Form;

use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Render\Element\PathElement;

/**
 * Class YesAuthConfigForm.
 */
class YesAuthConfigForm extends ConfigFormBase {

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames() {
    return [
      'yesauth.yesauthconfig',
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'yes_auth_config_form';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state) {
    $config = $this->config('yesauth.yesauthconfig');
    $form['yes_uri'] = [
      '#type' => 'url',
      '#title' => $this->t('YES Service URI'),
      '#description' => $this->t('Endpoint of yes service.'),
      '#default_value' => empty($config->get('yes_uri')) ? 'https://accounts.sandbox.yes.com' : $config->get('yes_uri'),
    ];
    $form['client_id'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Client Id'),
      '#description' => $this->t('Your yes.com client id as provided to you by yes.'),
      '#maxlength' => 128,
      '#size' => 64,
      '#default_value' => $config->get('client_id'),
    ];
    $form['tdt_claims'] = [
      '#type' => 'textfield',
      '#title' => $this->t('id_token claims'),
      '#description' => $this->t('Claims for id_token, separated by commas (i.e. [given_name, family_name, email]'),
      '#maxlength' => 240,
      '#size' => 64,
      '#default_value' => $config->get('tdt_claims'),
    ];
    $form['yes_ac_uri'] = [
      '#type' => 'url',
      '#title' => $this->t('Account Chooser Redirect URI'),
      '#description' => $this->t('The redierct uri you negotiated with yes to send users for the account chooser'),
      '#default_value' => $config->get('yes_ac_uri'),
    ];
    $form['redirect_uri'] = [
      '#type' => 'url',
      '#title' => $this->t('Redirect URI'),
      '#description' => $this->t('The redierct uri you negotiated with yes to send users to after the bank selection prozess'),
      '#default_value' => $config->get('redirect_uri'),
    ];
    $form['pem_client_cert_path'] = [
      '#type' => 'textfield',
      '#title' => $this->t('PEM Client Cert Path'),
      '#description' => $this->t('Path to your client certificate'),
      '#default_value' => $config->get('pem_client_cert_path'),
    ];
    $form['pem_cert_key'] = [
      '#type' => 'textfield',
      '#title' => $this->t('PEM Cert Key'),
      '#description' => $this->t('Key to your self signed certificate'),
      '#default_value' => $config->get('pem_cert_key'),
    ];
    $form['user_redir'] = array(
      '#type' => 'fieldset',
      '#title' => t('User destination pages'),
      '#description' => $this->t('Thus must be a path or route or your website.'),
      '#collapsible' => FALSE,
      '#collapsed' => FALSE,
    );
    $form['user_redir']['anon_dest'] = [
      '#type' => 'path',
      '#title' => $this->t('Anonymous visitors'),
      '#convert_path' => PathElement::CONVERT_NONE,
      '#description' => $this->t(''),
      '#default_value' => empty($config->get('anon_dest')) ? '<front>' : $config->get('anon_dest'),
    ];
    $form['user_redir']['auth_dest'] = [
      '#type' => 'path',
      '#title' => $this->t('Authenticated users'),
      '#convert_path' => PathElement::CONVERT_NONE,
      '#description' => $this->t(''),
      '#default_value' => empty($config->get('auth_dest')) ? '<front>' : $config->get('auth_dest'),
    ];


    $form['#validate'][] = [$this, 'checkFilesAndPaths'];

    return parent::buildForm($form, $form_state);
  }

  /**
   * @param array $form
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *
   */
  public function checkFilesAndPaths(array &$form, FormStateInterface $form_state) {
    $pem_cert_key = $form_state->getValue('pem_cert_key');
    $pem_client_cert_path = $form_state->getValue('pem_client_cert_path');
    if (!empty($pem_cert_key) && !file_exists($pem_cert_key)) {
      $form_state->setErrorByName("pem_cert_key", "PEM Cert Key File does not exist or is not readable");
    }
    if (!empty($pem_client_cert_path) && !file_exists($pem_client_cert_path)) {
      $form_state->setErrorByName("pem_client_cert_path", "PEM Client Cert File does not exist or is not readable");
    }
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    parent::submitForm($form, $form_state);

    $this->config('yesauth.yesauthconfig')
      ->set('client_id', $form_state->getValue('client_id'))
      ->set('tdt_claims', $form_state->getValue('tdt_claims'))
      ->set('yes_uri', $form_state->getValue('yes_uri'))
      ->set('redirect_uri', $form_state->getValue('redirect_uri'))
      ->set('yes_ac_uri', $form_state->getValue('yes_ac_uri'))
      ->set('pem_client_cert_path', $form_state->getValue('pem_client_cert_path'))
      ->set('pem_cert_key', $form_state->getValue('pem_cert_key'))
      ->set('anon_dest', $form_state->getValue('anon_dest'))
      ->set('auth_dest', $form_state->getValue('auth_dest'))
      ->save();

    // need to rebuild routing because of the URI settings
    \Drupal::service("router.builder")->rebuild();
  }

}
