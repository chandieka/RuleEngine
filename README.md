# SigmaConverter
A PHP script wrapper for MalwareBazaar API to convert the malware hashes into a Sigma Rule.

# Requirement
- PHP 8.0+
- PHP yaml extension

# Installation
Run this command.

`$ composer install`

# How to used?
Executing the command bellow will generate Sigma rule which are based malware filetypes.

`$ php sigma-filetype.php`

Executing the command bellow will generate Sigma rule which are based malware family.

`$ php sigma-signature.php`

Executing the command bellow will generate Sigma rule which are based the latest addition of malware to the MalwareBazaar.

`$ php sigma-recent-set.php`

# How does the script work?

All the script available in this project use curl to request a sets of information from a public API, there are 2 API that are used, which are MalwareBazaar and InQuestLabs.
Depending on the type of API call that was made the hashes from a given malware will be grouped into a certain descriptive namely either by filetype and signature (MalwareFamily).  