<?php
/*
 * Smime verify verifies .p7s certificate signature calling a 
 * proper php integrated openssl functions, then returns a 
 * related message to roundcube client side.
 * 
 * 0 - smime_verify is a subclass of  rcube_plugin
 * 1 - log file config parameter is properly set by calling rc framework
 * 2 - smime_verify->rcmail exists and is an instance of rcmail
 * 3 - smime_verify->rcmail has defined callback function for the hook 'message_load' 
 * 4 - 
 *
 *
 *
 */
class SMime_Verify_Plugin extends PHPUnit_Framework_TestCase
{

    function setUp()
    {
        include_once dirname(__FILE__) . '/../smime_verify.php';
    }

    /**
     * Plugin object construction test
     */
    function test_constructor()
    {
        $rcube  = rcube::get_instance();
        $plugin = new smime_verify($rcube->api);

        $this->assertInstanceOf('smime_verify', $plugin);
        $this->assertInstanceOf('rcube_plugin', $plugin);
    }



    public function testInitRcmail()
    {
      $rcube  = rcube::get_instance();
      $plugin = new smime_verify($rcube->api);
      $plugin->init();
      $this->assertInstanceOf('rcmail', $plugin->rcmail);  
    }
    
      public function testInitLogfile()
    {
      $rcube  = rcube::get_instance();
      $plugin = new smime_verify($rcube->api);
      $plugin->init();
      $this->assertTrue( $plugin->log_file );
    }

  public function testInitLogdebug()
    {
      $rcube  = rcube::get_instance();
      $plugin = new smime_verify($rcube->api);
      $plugin->init();
      $this->assertTrue( $plugin->log_debug === true || $plugin->log_debug === false );
    }

  public function testInitTempdir()
    {
      $rcube  = rcube::get_instance();
      $plugin = new smime_verify($rcube->api);
      $plugin->init();
      $this->assertTrue( !empty($plugin->rcmail->config->get('smime_verify_tempdir', '/tmp')) );
    }

}

