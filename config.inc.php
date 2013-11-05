<?php

// smime_verify plugin options
// --------------------------

// Temp directory for signatures validating. Default '/tmp'.
// Must be writeable by PHP process
$config['smime_verify_tempdir'] =  '/tmp';

// Log file for specific logging. Default 'smime_verify'.
$config['smime_verify_logfile'] =  'smime_verify';

// Debug logging. Default 'false'.
$config['smime_verify_debug'] =  'true';