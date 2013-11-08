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

  private $result;

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

    $this->log_debug = ($this->rcmail->config->get('smime_verify_debug') === 'true'); 
    
    $this->debug_log("Plugin init...");

    // message displaying hook: checking method
    if ($this->rcmail->action == 'show' || $this->rcmail->action == 'preview') {
      $this->add_hook('message_load', array($this, 'message_load'));
    }  
 
  }

  function is_tempdir_writable($tempdir){ //log callback 

       // tempdir does not exist
      if (!$tempdir){
      	$this->error_log('Unable to find temp directory');
      	return false;
      }
      
      // checks if tempdir exists (tries to create it otherwise) and is readable
      if (!file_exists($tempdir)){

      	$this->error_log("SMIME Verify temp directory ($tempdir) doesn't exists, SMIME Verify will try to create it...");

	// creation of tempdir is not possible
      	if( !mkdir($tempdir, 0700) ){
      	  $this->error_log("Unable to create SMIME Verify temp directory ($tempdir) ");
      	  return false;
      	}
      
      }
      
      // checks if tempdir is writable
      if (!is_writable($tempdir)){
      	$this->error_log("SMIME Verify temp directory ($tempdir) is not writable");
      	return false;
      }
      
      return true;
    
}	
 

  /**
   * Specific error logging for this extension.
   */
  function error_log($message){
      
    write_log($this->log_file, $message);
      
  }

  /**
   * Specific debug logging for this extension.
   */
  function debug_log($message){
   
     if ( $this->log_debug )
       write_log($this->log_file, $message);
      
  }

  /**
   * Injects HTML into message headers tables to show sign 
   * verification result 
   */
  function html_injector( $p, $injected_html){
    
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
   * Shows failed sign verification result
   */
  function messageheaders($p)
  {

    if ($this->result['valid']){
    
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

    }
    else{
      
      $ver_string = "FAILED";
      $message = "<b>La firma per questo messaggio non risulta verificata</b></br>";
    
    }

    $info_container = sprintf('<div id="smime_verify_info_container" style="visibility:hidden; width:0px; height:0px">%s</div>',
			      $message);

    // string containing data about signature verification
    $injected_html = sprintf('<td class="header-title">Verifica Firma</td>' . "\n".
			     '<td id="smime_verify_signature%s" class="header date">'.
			     '<img src="./plugins/smime_verify/img/firma%s.png" style="width:40px; height:27px" />'.
			     '</td>' . "\n",
			     $ver_string,
			     $ver_string);
    
    return $this->html_injector( $p, $injected_html . $info_container);
    
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

      $this->debug_log('Found signature to check for message with ID: ' . $message->uid );

      // retrieving tempdir config parameter
      $tempdir = $this->rcmail->config->get('smime_verify_tempdir', '/tmp');
      
      if (!$this->is_tempdir_writable($tempdir))
	return;
      
      // tempfile filenames 
      $message_filename = 'smime_verify' . $message->uid . '.eml';
      $cert_filename = 'smime_verify' . $message->uid  . '.pem'; 
      
      // creating and opening tempfiles 
      if ( !($message_filename = tempnam( $tempdir, $message_filename)) || !($fp = fopen($message_filename, 'w+')) ){
	$this->error_log('Error opening temp file ' . $message_filename . ' for signature verification' );
	return;
      }

      if ( !($cert_filename = tempnam( $tempdir, $cert_filename)) ){
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
      if ( $this->result['valid'] ){


/* 	array (size=12) */
/* 	  'name' => string '/C=IT/O=AcmePEC S.p.A./CN=Posta Certificata' (length=43) */
/*   'subject' =>  */
/* 	  array (size=3) */
/* 	  'C' => string 'IT' (length=2) */
/* 	  'O' => string 'AcmePEC S.p.A.' (length=14) */
/* 	  'CN' => string 'Posta Certificata' (length=17) */
/* 	  'hash' => string '01ebc369' (length=8) */
/*   'issuer' =>  */
/* 	  array (size=4) */
/* 	  'CN' => string 'Certificatore S.p.A.' (length=20) */
/* 	  'C' => string 'IT' (length=2) */
/* 	  'O' => string 'Certificatore1' (length=14) */
/* 	  'OU' => string 'Certification Service Provider' (length=30) */
/*   'version' => int 2 */
/* 	  'serialNumber' => string '2' (length=1) */
/* 	  'validFrom' => string '110609135257Z' (length=13) */
/* 	  'validTo' => string '140305135257Z' (length=13) */
/*   'validFrom_time_t' => int 1307627577 */
/*   'validTo_time_t' => int 1394027577 */
/*   'purposes' =>  */
/* 	  array (size=9) */
/*       1 =>  */
/* 	  array (size=3) */
/*           0 => boolean true */
/*           1 => boolean false */
/*           2 => string 'sslclient' (length=9) */
/*       2 =>  */
/* 	  array (size=3) */
/*           0 => boolean true */
/*           1 => boolean false */
/*           2 => string 'sslserver' (length=9) */
/*       3 =>  */
/* 	  array (size=3) */
/*           0 => boolean true */
/*           1 => boolean false */
/*           2 => string 'nssslserver' (length=11) */
/*       4 =>  */
/* 	  array (size=3) */
/*           0 => boolean true */
/*           1 => boolean false */
/*           2 => string 'smimesign' (length=9) */
/*       5 =>  */
/* 	  array (size=3) */
/*           0 => boolean true */
/*           1 => boolean false */
/*           2 => string 'smimeencrypt' (length=12) */
/*       6 =>  */
/* 	  array (size=3) */
/*           0 => boolean false */
/*           1 => boolean false */
/*           2 => string 'crlsign' (length=7) */
/*       7 =>  */
/* 	  array (size=3) */
/*           0 => boolean true */
/*           1 => boolean true */
/*           2 => string 'any' (length=3) */
/*       8 =>  */
/* 	  array (size=3) */
/*           0 => boolean true */
/*           1 => boolean false */
/*           2 => string 'ocsphelper' (length=10) */
/*       9 =>  */
/* 	  array (size=3) */
/*           0 => boolean false */
/*           1 => boolean false */
/*           2 => string 'timestampsign' (length=13) */
/*   'extensions' =>  */
/* 	  array (size=4) */
/* 	  'subjectKeyIdentifier' => string 'B4:CC:43:1D:CC:D9:F9:67:F8:98:4C:5E:BA:DF:32:DF:FB:5D:FD:8C' (length=59) */
/*       'authorityKeyIdentifier' => string 'keyid:BB:1D:4A:5E:90:DA:09:48:D8:E6:77:D2:B6:4A:BB:68:AE:41:9A:6F */
/* DirName:/CN=Certificatore S.p.A./C=IT/O=Certificatore1/OU=Certification Service Provider */
/* serial:01 */
/* ' (length=165) */
/* 	  'keyUsage' => string 'Digital Signature, Non Repudiation, Key Encipherment' (length=52) */
/* 	  'subjectAltName' => string 'email:posta-certificata@newsvilpec.babel.it' (length=43) */

	$this->debug_log('Veryfing signature: OK');	  


	$this->result['consegnatoa'] = $cert_info['subject']['CN'];
	$this->result['email'] = $cert_info['extensions']['subjectAltName'];
	$this->result['consegnatoda'] = $cert_info['issuer']['CN'];
	$this->result['validoda'] = strftime('%c', $cert_info['validFrom_time_t']); 
	$this->result['validofinoa'] = strftime('%c', $cert_info['validTo_time_t']); 
	$this->result['seriale'] = "";

      }
      else{

	$this->debug_log('Veryfing signature: INVALID');	        

      }

      $this->add_hook('template_object_messageheaders', array($this, 'messageheaders'));	  	
	
      // destroying tempfile
      unlink($message_filename);	
      unlink($cert_filename);	

    }

  }

}
