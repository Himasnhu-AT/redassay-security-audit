<?php
// The safe form of everything the PHP taint scanner flags. Not a real app.

// XSS: every reflected value is escaped on output.
$name = trim($_POST["name"] ?? "");
$email = trim($_POST["email"] ?? "");
?>
<form method="post">
    <input name="name" value="<?php echo htmlspecialchars($name, ENT_QUOTES, "UTF-8"); ?>">
    <input name="email" value="<?= htmlentities($email) ?>">
</form>
<?php

// File inclusion: request value mapped through a fixed allowlist.
$pages = ["home" => "home.php", "about" => "about.php"];
$key = $_GET["page"] ?? "home";
if (isset($pages[$key])) {
    include __DIR__ . "/pages/" . $pages[$key];
}

// SQL: prepared statement, value bound not interpolated.
$stmt = $db->prepare("SELECT id FROM users WHERE name = ?");
$stmt->execute([$_GET["q"] ?? ""]);

// Command: numeric coercion makes the value safe everywhere.
$count = intval($_GET["count"] ?? 0);
system("generate-report --count " . $count);

// File read: confined to a directory after basename + realpath.
$requested = basename($_GET["file"] ?? "");
$path = realpath(__DIR__ . "/data/" . $requested);
if ($path !== false && strpos($path, realpath(__DIR__ . "/data")) === 0) {
    echo htmlspecialchars(file_get_contents($path));
}

// Header redirect: only ever a relative path we control.
header("Location: /dashboard");
