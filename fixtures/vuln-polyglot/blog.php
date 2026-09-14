<?php
// VULN pack: php-taint. Request data reaching sinks through variables.

$name = trim($_POST["name"]);
$id = $_GET["id"];
$host = $_GET["host"];
?>
<!-- VULN: php.taint-xss -->
<input value="<?php echo $name; ?>">

<?php
// VULN: php.taint-file-inclusion
include($_GET["page"] . ".php");

// VULN: php.taint-sql
$rows = $db->query("SELECT * FROM users WHERE id = " . $id);

// VULN: php.taint-command
system("ping -c 1 " . $host);

// VULN: php.taint-file-read
$data = file_get_contents("/var/data/" . $_GET["file"]);

// VULN: php.taint-unserialize
$state = unserialize($_COOKIE["state"]);
