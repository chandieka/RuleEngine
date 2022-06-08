# SigmaConverter
A PHP script wrapper for MalwareBazaar API to convert the malware hashes into a Sigma Rule.
# Requirement
- PHP 8.0+
- PHP yaml extension
# Installation
Run this command
`$ composer install`
# How to used?
<p>Executing the command bellow will generate Sigma rule which are based malware filetypes</p>
`$ php sigma-filetype.php`
<p>Executing the command bellow will generate Sigma rule which are based malware family</p>
`$ php sigma-signature.php`
<p>Executing the command bellow will generate Sigma rule which are based the latest addition of malware to the MalwareBazaar</p>
`$ php sigma-recent-set.php`