<?php 
require __DIR__."/vendor/autoload.php";

const API_URL = "https://mb-api.abuse.ch/api/v1/";
const API_OPTION = [
    "query" => "get_recent",
    "selector" => "time"
];
const AUTHOR = "Chandieka";
const FILENAME = "malware.yaml";

$ruleArray = [
    "title" => "Known malware hash detected",
    "description" => "100 Hash of different malware",
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

$client = curl_init();

curl_setopt($client, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($client, CURLOPT_URL, API_URL);
curl_setopt($client, CURLOPT_POST, 1);
curl_setopt($client, CURLOPT_POSTFIELDS, API_OPTION);

echo "fetching latest malware hashes!\n";
$result = curl_exec($client);
curl_close($client);
$response = json_decode($result);
// file_put_contents('test.json', $result);

echo "Converting the hashes into a SIGMA rule!\n";
for ($i = 0; $i < count($response->data); $i++) {
    $hash = $response->data[$i];
    $ruleArray["detection"]['selection']["hash.sha256"][] = $hash->sha256_hash;
}
$ruleEncoded = yaml_emit($ruleArray);

echo "Outputing the rule to a ". FILENAME . "\n";

file_put_contents(FILENAME, $ruleEncoded);

echo "task completed!";
