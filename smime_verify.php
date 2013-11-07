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
  
  private $log_debug;


  /**
   * Plugin initialization.
   */
  function init()
  {
    $this->rcmail = rcmail::get_instance();       
    
    $this->load_config();
     
    $section = rcube_utils::get_input_value('_section', rcube_utils::INPUT_GET);

    $this->include_script('jquery.qtip.min.js');
    $this->include_stylesheet('jquery.qtip.min.css');
    $this->include_script('smime_verify.js');
    
    $this->log_file = $this->rcmail->config->get('smime_verify_logfile', 'smime_verify');

    if ( $this->rcmail->config->get('smime_verify_debug') === 'true' )
      $this->log_debug = true;
    else 
      $this->log_debug = false;
    
    $this->smime_verify_debug_log("Plugin init...");

    // message displaying hook: checking method
    if ($this->rcmail->action == 'show' || $this->rcmail->action == 'preview') {
      $this->add_hook('message_load', array($this, 'message_load'));
    }  
    
  }

  /**
   * Specific error logging for this extension.
   */
  function smime_verify_error_log($message){
      
    write_log($this->log_file, $message);
      
  }

  /**
   * Specific debug logging for this extension.
   */
  function smime_verify_debug_log($message){
   
     if ( $this->log_debug )
       write_log($this->log_file, $message);
      
  }

  /**
   * Injects HTML into message headers tables to show sign 
   * verification result 
   */
  function smime_verify_html_injector( $p, $injected_html){
    
    // retrieving skin name, different skins use different displaying methods                                                                               
    $skin = $this->rcmail->config->get('skin'); 

    // for classic skin is enough modify 'content' field of $p 
    if ( $skin == 'classic' || $p['id'] == 'preview-allheaders' ){

      // obtaining position for message headers table end tags
      $table_tail = "\n</tbody>\n</table>";
      $injection_point = strrpos( $p['content'], $table_tail );
      $new_html = substr( $p['content'], 0, $injection_point );

      // classic skin shows headers in a table, we need a new row 
      $injected_html = '<tr>' . $injected_html . '</tr>';
      
      // injecting concatenating table first part, new row, table end tags
      $new_html .= $injected_html . $table_tail ; 
      $p['content'] = $new_html ;  
    
    }

    // larry and babel skins use horizzontal showing 
    if ( ($skin == 'larry' || $skin == 'babel') && $p['valueof'] == 'date' )
      $p['content'] .= $injected_html;
	
    return $p;
  }

  /**
   * Shows successfull sign verification result
   */
  function smime_verify_messageheaders_OK($p)
  {
    
    // string containing data about signature verification
    $injected_html = "<td id=\"smime_verify_signature\" class=\"header-title\">Verifica Firma</td>\n".
      "<td class=\"header date\">OK</td>\n";
                      
    return $this->smime_verify_html_injector( $p, $injected_html);

  }
  
   /**
   * Shows failed sign verification result
   */
  function smime_verify_messageheaders_FAIL($p)
  {
    
    // string containing data about signature verification
    $injected_html = "<td id=\"smime_verify_signature\" class=\"header-title\">Verifica Firma</td>\n".
      "<td class=\"header date\">NON VALIDA</td>\n";

    return $this->smime_verify_html_injector( $p, $injected_html);

  }
    
  /**
   * Handler for message_load hook.
   * Checks message content for signature to check
   */
  function message_load($p)
  {
    
    $message = $p['object'];

    // message has signed content
    if ( $message->get_header('Content-Type') === 'multipart/signed'){      

      // retrieving tempdir config parameter
      $tempdir = $this->rcmail->config->get('smime_verify_tempdir', '/tmp');

      // tempdir does not exist
      if (!$tempdir){
      	$this->smime_verify_error_log('Unable to find temp directory');
      	return;
      }
      
      // checks if tempdir exists (tries to create it otherwise) and is readable
      if (!file_exists($tempdir)){

      	$this->smime_verify_error_log("SMIME Verify temp directory ($tempdir) doesn't exists, SMIME Verify will try to create it...");

	// creation of tempdir is not possible
      	if( !mkdir($tempdir, 0700) ){
      	  $this->smime_verify_error_log("Unable to create SMIME Verify temp directory ($tempdir) ");
      	  return;
      	}
      
      }
      
      // checks if tempdir is writable
      if (!is_writable($tempdir)){
      	$this->smime_verify_error_log("SMIME Verify temp directory ($tempdir) is not writable");
      	return;
      }
    
      $this->smime_verify_debug_log('Found signature to check for message with ID: ' . $message->uid );

      // tempfile filename uses unique message id
      $filename = 'smime_verify' . $message->uid; 
      
      // creating and opening tempfile 
      if ( !($filename = tempnam( $tempdir, $filename)) || !($fp = fopen($filename, 'w+')) ){
	
	$this->smime_verify_error_log('Error opening temp file ' . $filename . ' for signature verification' );
	return;
	
      }else{
	
	// gets message content, fills temp file, invokes openssl functions on it
	$this->smime_verify_debug_log('Using tempfile: ' . $filename . ' for signature verification' );
	
	$result = false;

	$this->rcmail->storage->get_raw_body($message->uid, $fp);    
      
	// verifies signature and choosing proper html generation function depending on result
	if( openssl_pkcs7_verify($filename, PKCS7_NOVERIFY)){
	  $this->smime_verify_debug_log('Veryfing signature: OK');	  
	  $this->add_hook('template_object_messageheaders', array($this, 'smime_verify_messageheaders_OK'));
	  $result = true;
	}
	else{
	  $this->smime_verify_debug_log('Veryfing signature: INVALID');	        
	  $this->add_hook('template_object_messageheaders', array($this, 'smime_verify_messageheaders_FAIL'));
	  $result = false;
	}
	
	// destroying tempfile
	unlink($filename);
	
	return $result;

      }

    }

  }

}
