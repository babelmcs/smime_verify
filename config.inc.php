<?php

// smime_verify plugin options
// --------------------------

// Temp directory for signatures validating. Default 'smime_verify/tmp'.
// Must be writeable by PHP process
$config['smime_verify_tempdir'] =  'smime_verify/tmp';

// Log file for specific logging. Default 'smime_verify'.
// Must be writeable by PHP process
$config['smime_verify_logfile'] =  'smime_verify';