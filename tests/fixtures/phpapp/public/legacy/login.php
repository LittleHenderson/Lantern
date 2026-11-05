<?php
require_once __DIR__ . '/db.php';

$user = $_POST['user'] ?? '';
$password = $_POST['password'] ?? '';
$hash = md5($password);
$res = mysqli_query($conn, "SELECT id FROM users WHERE name = '" . $user . "' AND pass = '$hash'");
?>
<html>
<body>
<p><?php echo "Hello " . $_GET['name']; ?></p>
</body>
</html>
