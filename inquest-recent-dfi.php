<?php
require __DIR__ . "/vendor/autoload.php";

use Ramsey\Uuid\Uuid;

const API_URL = "https://labs.inquest.net/api/dfi/list";
const AUTHOR = "Chandieka";

$directory = "rules-inquest-filetype-" . date("d-m-Y");

if (!file_exists($directory) && !is_dir($directory)) {
    mkdir($directory);
}

$client = curl_init();

curl_setopt_array($client, [
    CURLOPT_RETURNTRANSFER => 1,
    CURLOPT_URL => API_URL
]);

echo "fetching malware hashes!";

$result = curl_exec($client);
curl_close($client);
$response = json_decode($result);

$malicious = [];
$filetypes = [];
echo "Grouping hashes by classification!\n";
foreach ($response->data as $key => $value) {
    if ($value->classification == "MALICIOUS"){
        $malicious[] = $value;
        $filetypes[] = $value->file_type;
    }
}

$filetypes = array_values(array_unique($filetypes));

foreach ($filetypes as $filetype) {
    $ruleArray = [
        "title" => "Malware with $filetype file type is detected!",
        "id" => Uuid::uuid4()->toString(),
        "description" => "Up to 1337 Malware hashes with $filetype file type",
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
                "hash.sha256" => [],
            ],
            "condition" => "selection",
        ],
        "level" => "high"
    ];

    foreach ($malicious as $value) {
        if ($value->file_type == $filetype) {
            $ruleArray["detection"]["selection"]["hash.sha256"][] = $value->sha256;
        }
    }
    echo "Outputing the rule to a " . $filetype . ".yaml" . "\n";
    $ruleEncoded = yaml_emit($ruleArray);
    file_put_contents(__DIR__ . "/" .  $directory . "/" . $filetype . ".yaml", $ruleEncoded);
}
echo "task completed!";