<?php

require __DIR__ . '/vendor/autoload.php';

use \CheckRange\CheckRange as CheckRange;

$check = new CheckRange(["1.2.3.0/28"]);
$check->setFileSession("./session");
$check->setFileData("./data.xml");
$check->run();
