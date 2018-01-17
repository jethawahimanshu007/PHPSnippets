<!--This file generates is to save input Password in the database-->
<html>
<?php

function saveCredentials()
{

//Keeping the algorithm cost to 12, default is 10 but keeping above 10 is desired but not too high because of hw constraints
$hash = password_hash($_POST['pass'], PASSWORD_DEFAULT, ['cost' => 12]);

$checked = password_verify($_POST['password'], $hash);
if ($checked) {
    echo 'password correct';
} else {
    echo 'wrong credentials';
}
//Store this $hash as it is in the database against $_POST['user']
}
?>
</html>
