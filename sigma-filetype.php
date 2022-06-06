<?php
require __DIR__ . "/vendor/autoload.php";

use Ramsey\Uuid\Uuid;

$config = json_decode(file_get_contents(__DIR__ . "/config.json"));
const AUTHOR = "Chandieka";
const API_URL = "https://mb-api.abuse.ch/api/v1/";


$directory = "rules-filetype-" . date("d-m-Y");

if (!file_exists($directory) && !is_dir($directory)) {
    mkdir($directory);
}

foreach ($config->filetypes as $filetype) {
    $API_OPTION = [
        "query" => "get_file_type",
        "file_type" => "$filetype",
        "limit" => $config->limit
    ];

    $ruleArray = [
        "title" => "Malware with $filetype file type is detected!",
        "description" => "Up to 1000 Malware hash with $filetype file type",
        "reference" => [
            "All hash found in the rules can be found in https://bazaar.abuse.ch/"
        ],
        "author" => AUTHOR,
        "date" => date("d/m/Y"),
        "logsource" => [
            "product" => "zeek",
            "service" => "files"
        ],
        "detection" => [
            "selection" => [
                // "hash.md5" => [],
                "hash.sha256" => [],
            ],
            "condition" => "selection",
        ],
        "level" => "high"
    ];
    echo "Fetching malware hashes with $filetype file type!\n";

    $client = curl_init();
    
    curl_setopt($client, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($client, CURLOPT_URL, API_URL);
    curl_setopt($client, CURLOPT_POST, 1);
    curl_setopt($client, CURLOPT_POSTFIELDS, $API_OPTION);
    $result = curl_exec($client);
    
    curl_close($client);
    
    $response = json_decode($result);
    echo "Hashes fetched - Total: ". count($response->data) ."\n";
    
    // echo "Converting the hashes into a SIGMA rule!\n";
    for ($i = 0; $i < count($response->data); $i++) {
        $hash = $response->data[$i];
        $ruleArray["detection"]['selection']["hash.sha256"][] = $hash->sha256_hash;
    }

    $ruleEncoded = yaml_emit($ruleArray);
    echo "Outputing the rule to a " . $filetype . ".yaml" . "\n";
    file_put_contents(__DIR__ . "/" .  $directory . "/" . $filetype . ".yaml", $ruleEncoded);
    echo "waiting 5 seconds..\n";
    sleep(5);
    echo "--------------------------------------------------------------\n";
}
echo "task completed!";

