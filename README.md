

## Problem we Know about
- https://blog.sucuri.net/2015/05/fake-jquery-scripts-in-nulled-wordpress-pugins.html
- https://blog.sucuri.net/2015/11/jquery-min-php-malware-affects-thousands-of-websites.html
- https://blog.avast.com/wordpress-and-joomla-users-get-hacked-be-aware-of-fake-jquery

## Theory
I'm speculating the URI being requested can be tied to the bytes_in to detect variances and thereby detect anomolous or strange instances of those URIs.  I'm speculating that we can detect not only the malicious jquery javascript being requested (known problem space), but also detect other scripts or files being included which are abnormal and possibly malicious.

## Approach
Open data sets would need to show successful Internet access (proxy) logs, which show the URI and the

## Custom Data Parser (to move logs into csv format)
- https://github.com/cmeinco/proxy_log_analysis (YOU ARE HERE.)

## Supporting Datasets
- http://bluesmote.com/
- http://www.secrepo.com/squid/access.log.gz (needs review)


## TODO
[ ] Remove blocked/denied access from datasets, because it was blocked, ergo is "safe".
[ ] move todos to issues.
