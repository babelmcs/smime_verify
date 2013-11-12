<?php
/**
 +-------------------------------------------------------------------------+
 | smime_verify Plugin for Roundcube                                       |
 | Version 0.1                                                             |
 |                                                                         |  
 | This plugin provides SMIME signature verification for PEC messages.     |
 | It verifies signature of messages with MIME multipart/signed            |
 |                                                                         |
 | This program is free software; you can redistribute it and/or modify    |
 | it under the terms of the GNU General Public License version 2          |
 | as published by the Free Software Foundation.                           |
 |                                                                         |
 | This program is distributed in the hope that it will be useful,         |
 | but WITHOUT ANY WARRANTY; without even the implied warranty of          |
 | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           |
 | GNU General Public License for more details.                            |
 |                                                                         |
 | You should have received a copy of the GNU General Public License along |
 | with this program; if not, write to the Free Software Foundation, Inc., |
 | 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.             |
 |                                                                         |
 +-------------------------------------------------------------------------+
 | Author: Ramon Orrù                                                      |
 +-------------------------------------------------------------------------+
*/

class smime_verify extends rcube_plugin
{

  public $task = 'mail';

  private $rcmail;

  private $log_file;

  private $log_debug;

  private $result;

  /**
   * Plugin initialization.
   */
  public function init()
  {
    $this->rcmail = rcmail::get_instance();

    $this->load_config();

    $section = rcube_utils::get_input_value('_section', rcube_utils::INPUT_GET);

    $this->include_script('jquery.qtip.min.js');
    $this->include_stylesheet('jquery.qtip.min.css');
    $this->include_stylesheet('smime_verify.css');
    $this->include_script('smime_verify.js');

    $this->log_file = $this->rcmail->config->get('smime_verify_logfile', 'smime_verify');

    $this->log_debug = ($this->rcmail->config->get('smime_verify_debug') === 'true');

    $this->debug_log("Plugin init...");

    // message displaying hook: checking method
    if ($this->rcmail->action == 'show' || $this->rcmail->action == 'preview')
      $this->add_hook('message_load', array($this, 'message_load'));

  }

  public function is_tempdir_writable($tempdir)
  {
    // tempdir does not exist
    if (!$tempdir) {
      $this->error_log('Unable to find temp directory');
      return false;
    }

    // checks if tempdir exists (tries to create it otherwise) and is readable
    if (!file_exists($tempdir)) {
	
      $this->error_log("SMIME Verify temp directory ($tempdir) doesn't exists, SMIME Verify will try to create it...");
	
      // creation of tempdir is not possible
      if (!mkdir($tempdir, 0700)) {
	$this->error_log("Unable to create SMIME Verify temp directory ($tempdir) ");
	return false;
      }
	
    }
      
    // checks if tempdir is writable
    if (!is_writable($tempdir)) {
      $this->error_log("SMIME Verify temp directory ($tempdir) is not writable");
      return false;
    }
      
    return true;
      
  }
  
  /**
   * Specific error logging for this plugin
   */
  public function error_log($message)
  {
    
    write_log($this->log_file, $message);
    
  }
  
  /**
   * Specific debug logging for this plugin
   */
  public function debug_log($message)
  {
    
    if ( $this->log_debug )
      write_log($this->log_file, $message);
    
  }
  
  /**
   * Injects HTML into message headers tables to show sign
   * verification result
   */
  public function html_injector($p, $to_inject_short, $to_inject_all, $info_container)
  {
    
    //inserting a div as container for certificate information to show inside popups
    $short_headers_begin = '<table class="headers-table" id="preview-shortheaders"><tbody><tr>';
    $short_headers_begin_pos = strpos( $p['content'], $short_headers_begin );
    $p['content'] = substr_replace($p['content'], $info_container, $short_headers_begin_pos, 0);
    
    //some skins use 'short header table', with id="preview-shortheaders"
    $injected_html = $info_container . $short_headers_begin . "\n" . $to_inject_short;
    $p['content'] =  str_replace($short_headers_begin, $injected_html , $p['content']);

    // all skins use a table with id="preview-allheaders"
    $all_headers_begin = '<table id="preview-allheaders" class="headers-table">';
    $all_headers_begin_pos = strpos( $p['content'], $all_headers_begin );
    $table_tail = "\n</tbody>\n</table>";
    $injection_point = strpos( $p['content'], $table_tail, $all_headers_begin_pos );
    $p['content'] = substr_replace($p['content'], $to_inject_all, $injection_point, 0);

    return $p;
  }

  /**
   * Shows signature verification result, calls injector to insert html into page rendering
   */
  public function renderpage($p)
  {

    if ($this->result['valid']) {

      $ver_string = "OK";
      $message = sprintf('<b>Questo messaggio &egrave; firmato</b></br>'.
			 'Il messaggio non &egrave; stato modificato</br>'.
			 'Il certificato &egrave; verificato</br>'.
			 'L\'indirizzo mittente corrisponde al certificato allegato</br>'.
			 '</br><b>Info sul certificato:</b></br>'.
			 '<b>Consegnato a:</b> &nbsp; %s</br>'.
			 '<b>e-mail:</b> &nbsp; %s</br>'.
			 '<b>Consegnato da:</b> &nbsp; %s</br>'.
			 '<b>Valido da:</b> &nbsp; %s</br>'.
			 '<b>Valido fino a:</b> &nbsp; %s</br>'.
			 '<b>Seriale:</b> &nbsp; %s',
			 $this->result['consegnatoa'],
			 $this->result['email'],
			 $this->result['consegnatoda'],
			 $this->result['validoda'],
			 $this->result['validofinoa'],
			 $this->result['seriale']);

    } else {

      $ver_string = "FAILED";
      $message = "<b>La firma per questo messaggio non risulta verificata</b></br>";

    }

    $info_container = sprintf('<div class="smime_verify_info_container">%s</div>',
			      $message);

    // string containing data about signature verification
    $label = 'Verifica Firma';

    $injected_html_short = sprintf('<td class="header">'.
				   '<img class="smime_verify_signature%s" src="./plugins/smime_verify/img/firma%s.png"/>'.
				   '</td>' . "\n",
				   $ver_string,
				   $ver_string);

    $injected_html_all = sprintf("\n" . '<tr><td class="header-title">%s</td>' . "\n" . '%s</tr>' ,
				 $label,
				 $injected_html_short);


    return $this->html_injector( $p, $injected_html_short, $injected_html_all,  $info_container);

  }

  /**
   * Handler for message_load hook.
   * Checks message content for signature to check
   */
  public function message_load($p)
  {

    $message = $p['object'];

    // message has signed content
    if ($message->get_header('Content-Type') === 'multipart/signed') {

      $this->debug_log('Found signature to check for message with ID: ' . $message->uid );

      // retrieving tempdir config parameter
      $tempdir = $this->rcmail->config->get('smime_verify_tempdir', '/tmp');

      if (!$this->is_tempdir_writable($tempdir))
	return;

      // tempfile filenames
      $message_filename = 'smime_verify' . $message->uid . '.eml';
      $cert_filename = 'smime_verify' . $message->uid  . '.pem';

      // creating and opening tempfiles
      if ( !($message_filename = tempnam( $tempdir, $message_filename)) || !($fp = fopen($message_filename, 'w+')) ) {
	$this->error_log('Error opening temp file ' . $message_filename . ' for signature verification' );
	return;
      }

      if ( !($cert_filename = tempnam( $tempdir, $cert_filename)) ) {
	$this->error_log('Error creating temp file ' . $cert_filename . ' for certificate reading' );
	return;
      }

      // gets message content, fills temp file, invokes openssl functions on it
      $this->debug_log('Using tempfile: ' . $message_filename . ' for signature verification' );
      $this->debug_log('Using tempfile: ' . $cert_filename . ' for certificate reading' );

      $this->result = array();

      $this->rcmail->storage->get_raw_body($message->uid, $fp);

      // verifies signature
      $this->result['valid'] =  openssl_pkcs7_verify($message_filename, PKCS7_NOVERIFY, $cert_filename);

      $cert_info = array();
      $cert_content = file_get_contents($cert_filename);
      $cert_info = openssl_x509_parse( $cert_content );

      // choosing proper html generation function depending on result
      if ($this->result['valid']) {

	$this->debug_log('Veryfing signature: OK');

	$this->result['consegnatoa'] = $cert_info['subject']['CN'];
	$this->result['email'] = str_replace('email:', '', $cert_info['extensions']['subjectAltName']);
	$this->result['consegnatoda'] = $cert_info['issuer']['CN'];
	$this->result['validoda'] = strftime('%c', $cert_info['validFrom_time_t']);
	$this->result['validofinoa'] = strftime('%c', $cert_info['validTo_time_t']);

	$colon_position = strrpos( $cert_info['extensions']['authorityKeyIdentifier'], ':' );

	$this->result['seriale'] = ltrim(substr($cert_info['extensions']['authorityKeyIdentifier'] , $colon_position+1), '0');

      } else { 

	$this->debug_log('Veryfing signature: INVALID');

      }

      $this->add_hook('render_page', array($this, 'renderpage'));

      // destroying tempfiles
      unlink($message_filename);
      unlink($cert_filename);

    }

  }

}
