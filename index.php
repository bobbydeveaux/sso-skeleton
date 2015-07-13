<?php

function requestToken($url) {

    // create curl resource
    $ch = curl_init();

    // set url
    curl_setopt($ch, CURLOPT_URL, $url);

    //return the transfer as a string
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);

    // $output contains the output string
    $output = curl_exec($ch);

    // close curl resource to free up system resources
    curl_close($ch);

    $token = json_decode($output, true);

    //var_dump($token);
    return $token['id'];

}

    if (true === isset($_GET['code'])) {
        $url = "http://sso-skeleton.local/token?grant_type=authorization_code&client_id=bobbydev&client_secret=12345&code=" . $_GET['code'] . "&redirect_uri=http://bobbydev.local";
        echo '<a href="' . $url . '">3rd Party Token</a>';
    }

    if (true === isset($_POST['username'])) {
        $url = "http://sso-skeleton.local/token?grant_type=password&client_id=bobbydev&client_secret=12345&username=" . $_POST['username'] . "&password=" . $_POST['password'] . "&redirect_uri=http://bobbydev.local";
        $userId = requestToken($url);

        if (false === empty($userId)) {
            echo 'Welcome ' . $userId;
        } else {
            echo 'Sorry, Access denied';
        }

        exit;
    }

    $options = [
        'cost' => 11,
        'salt' => mcrypt_create_iv(22, MCRYPT_DEV_URANDOM),
    ];

    // username and password is username / password
    echo password_hash("password", PASSWORD_BCRYPT, $options)."<br /><br />";

    ?>


    <a href="http://sso-skeleton.local/authorization?accept=yep&response_type=code&client_id=bobbydev&redirect_uri=http://bobbydev.local">3rd Party Login</a>

    <h1>Welcome to BobbyDev Website</h1>
    <h2>Please login</h2>
    <form method="post">
        <input type="text" name="username" /><br/>
        <input type="password" name="password" /><br/>
        <input type="submit" value="Login" />
    </form>
