<?php
require __DIR__ . "/vendor/autoload.php";

use Ramsey\Uuid\Uuid;

const API_URL = "https://mb-api.abuse.ch/api/v1/";
const API_OPTION = [
    "query" => "get_recent",
    "selector" => "time"
];
const AUTHOR = "Chandieka";

$directory = "rules-recent-set-" . date("d-m-Y");

if (!file_exists($directory) && !is_dir($directory)) {
    mkdir($directory);
}

echo "fetching latest malware hashes\n";

$client = curl_init();

curl_setopt($client, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($client, CURLOPT_URL, API_URL);
curl_setopt($client, CURLOPT_POST, 1);
curl_setopt($client, CURLOPT_POSTFIELDS, API_OPTION);

$result = curl_exec($client);
curl_close($client);
$response = json_decode($result);
// file_put_contents('test.json', $result);
echo "Hashes fetched - Total: " . count($response->data) . "\n";

echo "Grouping the hashes to their malware family \n";
$signatures = [];
foreach ($response->data as $key => $item) {
    $signatures[] = $item->signature;
}

$signatures = array_values(array_unique($signatures));
$families = [];
for ($i = 0; $i < count($signatures); $i++) {
    $sig = $signatures[$i];
    $families["$sig"] = [];
    for ($j = 0; $j < count($response->data); $j++) {
        if ($response->data[$j]->signature == $sig) {
            array_push($families["$sig"], $response->data[$j]);
        }
    }
}

echo count($signatures) . " Malware family found!" . "\n";

foreach ($families as $signature => $hashes) {
    echo "Converting the hashes into a SIGMA rule!\n";

    if ($signature != null) {
        $sig = $signature;
    } else {
        $sig = "Unknown";
    }

    $ruleArray = [
        "title" => $sig . " Malware family is detected!",
        "id" => Uuid::uuid4()->toString(),
        "description" => "All the hashes for $sig family found in MalwareBazaar recent addition",
        "reference" => [
            "All hash found in the rules can be found in https://bazaar.abuse.ch/"
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

    foreach ($hashes as $hash) {
        $ruleArray["detection"]["selection"]["hash.sha256"][] = $hash->sha256_hash;
    }

    $ruleEncoded = yaml_emit($ruleArray);
    echo "Outputing the rule to " . $sig . ".yaml" . "\n";
    file_put_contents(__DIR__ . "/" .  $directory . "/" . $sig . ".yaml", $ruleEncoded);
    echo "--------------------------------------------------------------\n";
}
echo "task completed!";
