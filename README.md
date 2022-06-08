# SigmaConverter
A PHP script wrapper for MalwareBazaar API to convert the malware hashes into a Sigma Rule.
# Requirement
- PHP 8.0+
- PHP yaml extension
# Installation
Run this command
`$ composer install`
# How to used?
Executing the command bellow will generate Sigma rule which are based malware filetypes
`$ php sigma-filetype.php`
Executing the command bellow will generate Sigma rule which are based malware family
`$ php sigma-signature.php`
Executing the command bellow will generate Sigma rule which are based the latest addition of malware to the MalwareBazaar
`$ php sigma-recent-set.php`