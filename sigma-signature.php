<?php 
require __DIR__."/vendor/autoload.php";

$config = json_decode(file_get_contents(__DIR__ . "/config.json"));

const API_URL = "https://mb-api.abuse.ch/api/v1/";
const AUTHOR = "Chandieka";
const FILENAME = "malware.yaml";
const DIRECTORY = "rules";


$ruleArray = [
    "title" => "",
    // "id" => uniqid(),
    "description" => "TEST",
    "reference" => [
        "All hash found in the rules is source from https://bazaar.abuse.ch/"
    ],
    "author" => AUTHOR,
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

if (!file_exists(DIRECTORY) && !is_dir(DIRECTORY)) {
    mkdir(DIRECTORY);
} 

foreach ($config->signatures as $key => $signature) {
    $option = [
        "query" => "get_siginfo",
        "signature" => $signature,
        "selector" => $config->limit
    ];

    $ruleArray['title'] = $signature . " Malware family is detected!";

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
    
    file_put_contents(__DIR__ . "/" .  DIRECTORY . "/". $signature . ".yaml", $ruleEncoded);
    
    echo "waiting 5 seconds..\n";
    sleep(5);
    echo "--------------------------------------------------------------\n";
}

echo "task completed!";
