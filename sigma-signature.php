<?php 
require __DIR__."/vendor/autoload.php";

use Ramsey\Uuid\Uuid;

$config = json_decode(file_get_contents(__DIR__ . "/config.json"));

const API_URL = "https://mb-api.abuse.ch/api/v1/";
const AUTHOR = "Chandieka";
const FILENAME = "malware.yaml";
$directory = "rules-signature-".date("d-m-Y");

if (!file_exists($directory) && !is_dir($directory)) {
    mkdir($directory);
} 

foreach ($config->signatures as $key => $signature) {
    $ruleArray = [
        "title" => "Malware with $filetype file type is detected!",
        "id" => Uuid::uuid4()->toString(),
        "description" => "Up to $config->limit malware hashes",
        "reference" => [
            "All hash found in the rules can be found in https://labs.inquest.net/",
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

    $option = [
        "query" => "get_siginfo",
        "signature" => $signature,
        "selector" => $config->limit
    ];
    
    echo "fetching latest malware hashes for $signature malware family!\n";
    $client = curl_init();
    curl_setopt($client, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($client, CURLOPT_URL, API_URL);
    curl_setopt($client, CURLOPT_POST, 1);
    curl_setopt($client, CURLOPT_POSTFIELDS, $option);
    $result = curl_exec($client);
    curl_close($client);
    $response = json_decode($result);
    
    echo "Converting the hashes into a SIGMA rule!\n";
    for ($i = 0; $i < count($response->data); $i++) {
        $hash = $response->data[$i];
        $ruleArray["detection"]['selection']["hash.sha256"][] = $hash->sha256_hash;
    }
    $ruleEncoded = yaml_emit($ruleArray);
    
    echo "Outputing the rule to a ". $signature. ".yaml" . "\n";
    
    file_put_contents(__DIR__ . "/" .  $directory . "/". $signature . ".yaml", $ruleEncoded);
    
    echo "waiting 5 seconds..\n";
    sleep(5);
    echo "--------------------------------------------------------------\n";
}

echo "task completed!";
