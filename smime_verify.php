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

/*
    This class contains only hooks and action handlers.
*/

class smime_verify extends rcube_plugin
{
  public $task = 'mail';
  public $engine;

  private $rcmail;

  private $env_loaded;
  private $message;
  private $keys_parts = array();
  private $keys_bodies = array();

  private $log_file;


  /**
   * Plugin initialization.
   */
  function init()
  {
    $this->rcmail = rcmail::get_instance();       

    $section = rcube_utils::get_input_value('_section', rcube_utils::INPUT_GET);

    $this->log_file = 'smime_verify';
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

  function log_this($message){
      
    write_log($this->log_file, $message);
      
  }


 
  
    /**
     * Handler for message_part_structure hook.
     * Called for every part of the message.
     *
     * @param array Original parameters
     *
     * @return array Modified parameters
     */
  function parse_structure($p)
  {
    $this->log_this('Message mimetype: ' . $p['mimetype']);
    $this->log_this('Message structure' . print_r($p['structure'], true));
    // senza envelop
    if ($p['mimetype'] == 'multipart/signed') {
      $this->parse_signed($p['structure']);
    } // envelop
    else if ($p['mimetype'] == 'application/pkcs7-mime') {
      //      $this->parse_encrypted($p);
    }    
    return $p;
  }

  function parse_signed($structure){

        /* if ($struct->parts[1] && $struct->parts[1]->mimetype == 'application/pkcs7-signature') { */

	/*     $verified = openssl_pkcs7_verify("/home/loudgefly/email_sign_ok.eml", PKCS7_NOVERIFY); */
	    												     
        /* } */
  }


  /**
   * Verify signed messages (SQ)
   *
   */
  function smime_header_verify_do()
  {

    global $imapConnection, $passed_ent_id, $passed_id, $color, $message,
      $mailbox, $where, $what, $startMessage, $uid_support,
      $row_highlite_color;


    // grab the sender address
    $sender_address = '';
    if (!empty($message->rfc822_header->from[0]->mailbox))
      $sender_address = (!empty($message->rfc822_header->from[0]->host)
                      ? $message->rfc822_header->from[0]->mailbox
                        . '@' . $message->rfc822_header->from[0]->host
			 : $message->rfc822_header->from[0]->mailbox);


    if ($message->header->type0 == 'application' and $message->header->type1 == 'pkcs7-mime')
      {

	sq_change_text_domain('smime');

	// Output for SM 1.5.2+
	//
	if (check_sm_version(1, 5, 2))
	  {
	    global $oTemplate;
	    $oTemplate->assign('row_highlite_color', $row_highlite_color);
	    $output = $oTemplate->fetch('plugins/smime/encrypted.tpl');
	    return array('read_body_header' => $output);
	  }


	// Output for SM 1.4.x
	else
	  {

	    /* ---------------------
   This had been used to place a kind of "section"
   that made the signed information more prominent
         echo "      <tr>\n"
            . "         <th bgcolor=\"$color[9]\" align=\"left\" valign=\"top\" colspan=\"3\">\n"
            . '           ' . _("This message has been S/MIME encrypted") . "\n"
            . "         </th>\n"
            . "      </tr>\n";
	    ------------------------- */

         echo "      <tr bgcolor=\"" . $row_highlite_color . "\">\n"
            . "        <td width=\"20%\" align=\"right\" valign=\"top\">\n<b>"
	   . _("S/MIME Encrypted By:")
            . "        </b></td><td width=\"80%\" valign=\"top\">\n"
	   . _("Unknown")
            . "        </td>\n"
	   . "      </tr>\n";

	  }

	sq_change_text_domain('squirrelmail');

      }      

    if ($message->header->type0 == 'multipart' and $message->header->type1 == 'signed')
      {
	$cmd = "FETCH $passed_id BODY.PEEK[HEADER.FIELDS (Content-Type)]";
	$read = sqimap_run_command($imapConnection, $cmd, true, $response, $mess, $uid_support);

	if (preg_match('/protocol=(")?application\/(x-)?pkcs7-signature(")?/i', implode('', $read)))
	  {

	    // we have a detatched s/mime message
	    //
	    // we remove the MIME signature entity from the message here
	    // so that SquirrelMail does not try to present it to the user
	    //
	    // previously array_pop was done unconditionally to remove the
	    // signature entity, but SM was then popping off one entity
	    // every time the message was viewed, which is wrong.
	    // instead, loop through entities and remove just the signature part
	    //
	    $entity_index_to_unset = -1;
	    foreach ($message->entities as $i => $entity)
	      {
		if (is_object($entity)
		    && strtolower(get_class($entity)) == 'message'
             && $entity->type0 == 'application'
		    && strpos($entity->type1, 'pkcs7-signature') !== FALSE)
		  {
		    $entity_index_to_unset = $i;
		    break;
		  }
	      }
	    if ($entity_index_to_unset > -1)
	      unset($message->entities[$entity_index_to_unset]);


	    // Not sure why this was needed, but it was not doing anything
	    // immediately useful beside b0rking the attachment.  W/out this
	    // it correctly hides the s/mime sig attachment, at least in limited
	    // testing w/out any other attachments
	    // 
	    // It was probably related to problems with the array_pop above,
	    // which (see notes above) has been fixed in a better way
	    /*
         if (!isset($message->entities[1]))
         {
            $message->header->type0     = $message->entities[0]->header->type0;
            $message->header->type1     = $message->entities[0]->header->type1;
            $message->header->charset   = $message->entities[0]->header->parameters->charset;
            $message->header->encoding  = $message->entities[0]->header->encoding;
            $message->header->size      = $message->entities[0]->header->size;
            $message->header->filename  = $message->entities[0]->header->disposition->properties->filename;
            $message->header->entity_id = $message->entities[0]->header->entity_id;
            $message->entities          = $message->entities[0]->entities;
         }
	    */

	    $body = mime_fetch_full_body ($imapConnection, $passed_id);
	    list ($retval, $lines, $name, $cert) = verify_smime($body, $sender_address);
	    $verify_status = convert_verify_result_to_displayable_text($retval);


	    $signed_parts = signed_parts($lines);


	    sq_change_text_domain('smime');


	    // build links
	    //
	    $download_link = sqm_baseuri() . 'plugins/smime/downloadcert.php?cert=' . $cert;
	    if ($where && $what)
	      $view_link = sqm_baseuri() . 'plugins/smime/viewcert.php?mailbox=' . urlencode($mailbox) . "&passed_id=$passed_id&where=" . urlencode($where) . "&what=" . urlencode($what) . "&cert=" . $cert;
	    else
	      $view_link = sqm_baseuri() . 'plugins/smime/viewcert.php?mailbox=' . urlencode($mailbox) . "&passed_id=$passed_id&startMessage=$startMessage&show_more=0&cert=" . $cert;


	    if (check_sm_version(1, 5, 2))
	      {
		$view_tag = create_hyperlink($view_link, _("View Certificate"));
		$download_tag = create_hyperlink($download_link, _("Download Certificate"));
	      }
	    else
	      {
		$view_tag = '<a href="' . $view_link . '">' . _("View Certificate") . '</a>';
		$download_tag = '<a href="' . $download_link . '">' . _("Download Certificate") . '</a>';
	      }


	    $tworows = ($retval == 0 || $retval == 6);


	    if ($retval == 0)
	      $signer_verified = TRUE;
	    else
	      $signer_verified = FALSE;



	    // Output for SM 1.5.2+
	    //
	    if (check_sm_version(1, 5, 2))
	      {
		global $oTemplate;
		$oTemplate->assign('row_highlite_color', $row_highlite_color);
		$oTemplate->assign('signer_verified', $signer_verified);
		$oTemplate->assign('signer', $name . _(", ") . $verify_status, FALSE);
		$oTemplate->assign('view_tag', $view_tag, FALSE);
		$oTemplate->assign('download_tag', $download_tag, FALSE);
		if ($tworows)
		  $oTemplate->assign('signed_parts', $signed_parts);
		else
		  $oTemplate->assign('signed_parts', '');
		$output = $oTemplate->fetch('plugins/smime/signed.tpl');
		return array('read_body_header' => $output);
	      }


	    // Output for SM 1.4.x
	    else
	      {

		/* ---------------------
   This had been used to place a kind of "section"
   that made the signed information more prominent
            echo "      <tr>\n"
               . "         <th bgcolor=\"$color[9]\" align=\"left\" valign=\"top\" colspan=\"3\">\n"
               . "           " . _("This message has been S/MIME signed") . "\n"
               . "         </th>\n"
               . "      </tr>\n";
	       ------------------------- */


		$colortag1 = '';
		$colortag2 = '';
		if (!$signer_verified)
		  {
		    $colortag1 = "<font color=\"$color[2]\"><b>";
		    $colortag2 = '</b></font>';
		  }

            echo "      <tr bgcolor=\"$row_highlite_color\">\n"
               . "        <td width=\"20%\" align=\"right\" valign=\"top\">\n<b>"
	      . _("S/MIME Signed By:")
               . "        </b></td><td width=\"80%\" valign=\"top\">\n"
               . "          <table width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\">\n"
               . "            <tr>\n"
               . "              <td valign=\"top\" align=\"left\">\n"
	      . "                $colortag1 $name" . _(", ") . "$verify_status$colortag2\n"
               . "              </td>\n"
               . "              <td valign=\"top\" align=\"right\" nowrap><small>\n"
	      . "                $view_tag\n";

            if (!$tworows)
	      echo "<br />\n     $download_tag\n";

            echo "                </small></td>\n"
               . "            </tr>\n"
               . "          </table>\n"
               . "        </td>\n"
	      . "      </tr>\n";


            if ($tworows)
	      {
               echo "      <tr bgcolor=\"$row_highlite_color\">\n"
                  . "         <td width=\"15%\" align=\"right\" valign=\"top\"><b>\n"
		 . _("Signed Parts:")
                  . "         </b></td><td width=\"85%\" valign=\"top\">\n"
                  . "            <table width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\">\n"
                  . "              <tr>\n"
                  . "                <td valign=\"top\" align=\"left\">\n"
                  . "                  $signed_parts\n"
                  . "               </td>\n"
                  . "               <td valign=\"top\" align=\"right\" nowrap><small>\n"
                  . "                 $download_tag\n"
                  . "               </small></td>\n"
                  . "            </tr>\n"
                  . "          </table>\n"
                  . "        </td>\n"
		 . "      </tr>\n";

	      }

	      }

	    sq_change_text_domain('squirrelmail');

	  }

      }

  }



    
    /**
     * Handler for message_load hook.
     * Check message bodies and attachments for keys/certs.
     */
    function message_load($p)
    {
      $message = $p['object'];
    
      $filename = './tmp/' . $message->uid . '.eml';
      if ( !( $fp = fopen($filename, 'w+')) ){
	$this->log_this('Error opening ' . $filename );
      }else{
	$this->rcmail->storage->get_raw_body($message->uid, $fp);
      
	fclose($fp);
      
	if( openssl_pkcs7_verify($filename, PKCS7_NOVERIFY))
	  $this->log_this('Veryfing signature: OK');
	else
	  $this->log_this('Veryfing signature: INVALID');
      }
      
    }

}
