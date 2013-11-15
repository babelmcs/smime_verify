<?php

// smime_verify plugin options
// --------------------------

 /* github version of rc uses '$config' array to store plugins 
  * config option, while older versions use '$rcmail_config'
  * here is used a bad hack (writing values in both) 
  * for avoid empty conf arrays on some versions
  */


// Temp directory for signatures validating. Default '/tmp'.
// Must be writeable by PHP process
$config['smime_verify_tempdir'] =  '/tmp';

// Log file for specific logging. Default 'smime_verify'.
$config['smime_verify_logfile'] =  'smime_verify';

// Debug logging. Default 'false'.
$config['smime_verify_debug'] =  'false';

// Temp directory for signatures validating. Default '/tmp'.
// Must be writeable by PHP process
$rcmail_config['smime_verify_tempdir'] =  '/tmp';

// Log file for specific logging. Default 'smime_verify'.
$rcmail_config['smime_verify_logfile'] =  'smime_verify';

// Debug logging. Default 'false'.
$rcmail_config['smime_verify_debug'] =  'false';
