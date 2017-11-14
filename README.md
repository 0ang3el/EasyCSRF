## EasyCSRF extension for Burp

EasyCSRF helps to find CSRF vulnerabilities as the result of bypassing weak CSRF-protection. For explanation how some bypasses for CSRF-protection are working, look at the slides from [ZeroNights 2017](https://2017.zeronights.org/report/tricks-bypassing-csrf-protection/) conference.

Extension automatically makes changes to all POST/PUT/DELETE/PATCH requests and highlights modified requests in Proxy HTTP history. You role is to judge by looking at WebApp UI which modified requests are failed/succeeded. When installing EasyCSRF extension, **EasyCSRF** tab with configuration is added.

Following modifications for requests are supported:
* Remove CSRF-token from parameters. URL-encoded, multipart, JSON parameters are supported.
* Remove HTTP headers that are used for CSRF-protection.
* Change PUT/DELETE/PATCH method to POST.
* Convert URL-encoded body to JSON format.
* Set text/plain value for Content-Type header.
* Change POST/PUT/DELETE/PATCH request to GET request for url-encoded body.

First four methods are turned on by default.

Extension works with [Burp Suite Free Edition](https://portswigger.net/burp/freedownload).