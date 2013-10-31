<?php
/*
 +-------------------------------------------------------------------------+
 | smime_verify Plugin for Roundcube                                             |
 | Version 0.1                                                             |
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
 | Author: Ramon                                                           |
 +-------------------------------------------------------------------------+
*/

class smime_verify extends rcube_plugin
{

  public $task = 'mail';

  private $rcmail;

  private $log_file;

  /**
   * Plugin initialization.
   */
  function init()
  {
    $this->rcmail = rcmail::get_instance();       

    $section = rcube_utils::get_input_value('_section', rcube_utils::INPUT_GET);

    $this->log_file = $this->rcmail->config->get('smime_verify_logfile', 'smime_verify');
    $this->log_this("Plugin init...");

    if ($this->rcmail->task == 'mail') {
      // message parse/display hooks
      //$this->add_hook('message_part_structure', array($this, 'parse_structure'));
      //$this->add_hook('message_body_prefix', array($this, 'status_message'));

      // message displaying
      if ($this->rcmail->action == 'show' || $this->rcmail->action == 'preview') {
	$this->add_hook('message_load', array($this, 'message_load'));
	// $this->add_hook('template_object_messagebody', array($this, 'message_output'));
	// $this->register_action('plugin.smime_verifyimport', array($this, 'import_file'));
      }
    }
  }

  /**
   * Specific logging for this extension.
   */
  function log_this($message){
      
    write_log($this->log_file, $message);
      
  }
    
  /**
   * Handler for message_load hook.
   * Check message bodies and attachments for keys/certs.
   */
  function message_load($p)
  {

    $message = $p['object'];

    if ( $message->get_header('Content-Type') === 'multipart/signed'){      

      $homedir = $this->rcmail->config->get('smime_verify_tempdir', INSTALL_PATH . 'plugins/smime_verify/tmp');

      if (!$homedir){
	$this->log_this('Unable to find SMIME Verify temp directory config option');
	return;
      }
      
      // check if homedir exists (create it if not) and is readable                                                                                         
      if (!file_exists($homedir)){

	$this->log_this('SMIME Verify temp directory ($homedir) doesn\'t exists, SMIME Verify will try to create it...');

	if( !mkdir($homedir, 0700) ){
	  $this->log_this('Unable to create SMIME Verify temp directory ($homedir)');
	  return;
	}
      
      }
      
      if (!is_writable($homedir)){
	$this->log_this('SMIME Verify temp directory ($homedir) is not writable');
	return;
      }      
    
      $filename = $homedir . '/' . $message->uid . '.eml';
      
      if ( !($fp = fopen($filename, 'w+')) ){
	
	$this->log_this('Error opening temp file ' . $filename . ' for signature verification' );
	return;
	
      }else{
      
	$this->rcmail->storage->get_raw_body($message->uid, $fp);
      
	fclose($fp);
      
	if( openssl_pkcs7_verify($filename, PKCS7_NOVERIFY)){
	  $this->log_this('Veryfing signature: OK');
	  return true;
	}
	else{
	  $this->log_this('Veryfing signature: INVALID');
	  return false;
	}

      }

    }

  }

    
  /*   /\** */
  /*    * Handler for message_part_structure hook. */
  /*    * Called for every part of the message. */
  /*    * */
  /*    * @param array Original parameters */
  /*    * */
  /*    * @return array Modified parameters */
  /*    *\/ */
  /* function parse_structure($p) */
  /* { */
  /*   $this->log_this('Message mimetype: ' . $p['mimetype']); */
  /*   $this->log_this('Message structure' . print_r($p['structure'], true)); */
  /*   // senza envelop */
  /*   if ($p['mimetype'] == 'multipart/signed') { */
  /*     $this->parse_signed($p['structure']); */
  /*   } // envelop */
  /*   else if ($p['mimetype'] == 'application/pkcs7-mime') { */
  /*     //      $this->parse_encrypted($p); */
  /*   }     */
  /*   return $p; */
  /* } */


}
