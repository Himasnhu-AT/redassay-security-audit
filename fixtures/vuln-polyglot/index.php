<?php
// VULN pack: php-ruby

// VULN: php.file-inclusion-superglobal
include($_GET['page']);

// VULN: php.sql-superglobal
mysqli_query($conn, "SELECT * FROM u WHERE n = '" . $_POST['name'] . "'");

// VULN: php.weak-comparison-hash
if ($stored == md5($input)) { login(); }

// VULN: php.extract-superglobal
extract($_GET);
