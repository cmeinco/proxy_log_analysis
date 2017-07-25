

## Problem we know about
- https://blog.sucuri.net/2015/05/fake-jquery-scripts-in-nulled-wordpress-pugins.html
- https://blog.sucuri.net/2015/11/jquery-min-php-malware-affects-thousands-of-websites.html
- https://blog.avast.com/wordpress-and-joomla-users-get-hacked-be-aware-of-fake-jquery

## Theory
I'm speculating the URI being requested can be tied to the bytes_in to detect variances and thereby detect anomalous or strange instances of those URIs.  I'm speculating that we can detect not only the malicious jquery javascript being requested (known problem space), but also detect other scripts or files being included which are abnormal and possibly malicious.

## Approach
[ ] Explore the data, eat some food, drink some beer, explore data more; repeat.

## Custom Data Parser (to move logs into csv format)
- https://github.com/cmeinco/proxy_log_analysis (YOU ARE HERE.)

## Supporting Datasets
- http://bluesmote.com/ (use SGreadlog.py)
- http://www.secrepo.com/squid/access.log.gz (use SQreadlog.py)

## TODO
 [ ] Remove blocked/denied access from datasets, because it was blocked, ergo is "safe".
 [ ] move todos to issues.
