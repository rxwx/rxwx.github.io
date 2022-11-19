---
layout: post
title:  ProxyNotRelay
tags: vuln exploit 0day exchange
---

# ProxyNotRelay - An Exchange Vulnerability Encore


In this blog post we will dive into the latest Microsoft Exchange 0-day vulnerability, dubbed #ProxyNotShell, how it relates to other Exchange vulnerabilities and finally demonstrate how ProxyRelay can combined with ProxyNotShell, even with Extended Protection and IIS rewrite rules enabled.

However, before we jump in, I just want to clarify that the patches are [now](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41040) [available](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41082). If you are running a vulnerable verison of Exchange - stop now and go and install the patches. Do not rely on the mitigations! I also wrote the majority of this post before the patches were released, so please save me the job of doing `sed s/\bis\b/\bwas\b/g blog.md`! 😉

## Proxy (Not?) Shell

In late September 2022, the [GTSC team released an advisory](https://www.gteltsc.vn/blog/warning-new-attack-campaign-utilized-a-new-0day-rce-vulnerability-on-microsoft-exchange-server-12715.html) stating that they had detected exploitation of a Microsoft Exchange 0-day vulnerability in the wild. Whilst not many details were immediately available, and there was some confusion about whether this _really was an unpatched 0-day,_ Microsoft later clarified that there was indeed two vulnerabilities being exploited to achieve RCE, in [their own advisory](https://msrc-blog.microsoft.com/2022/09/29/customer-guidance-for-reported-zero-day-vulnerabilities-in-microsoft-exchange-server/).

These vulnerabilities were given two CVE numbers.

-   [CVE-2022–41040](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41040)— An SSRF vulnerability (interestingly, in the advisory it’s described as Elevation of Privilege)
-   [CVE-2022–41082](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41082)— A Remote Code Execution vulnerability in the PowerShell component

Sounds [pretty familiar](https://www.zerodayinitiative.com/blog/2021/8/17/from-pwn2own-2021-a-new-attack-surface-on-microsoft-exchange-proxyshell) huh?

![Extract from the ZDI blog for ProxyShell, detailing the three bugs used in the ProxyShell chain](/public/media/ProxyShell-CVEs.png)

In fact, if we have a look at the GTSC advisory, they state the same thing!

  ![Extract from the GTSC advisory stating that the request path is the same as ProxyShell](/public/media/GTSC-advisory.png)

So from reading both the Microsoft and GTSC advisories we can ascertain that the ProxyShell path confusion is being used. But how? Wasn’t it patched under CVE-2021–34473?

Well, not exactly. In fact, the only change that was made to break the path-confusion was to make the Exchange front-end no longer automatically authenticate to the backend with the machine account.

![Orange’s ProxyShell blog showing SSRF patch](/public/media/ProxyShell-diff.png)

The post-auth RCE was fixed by limiting the file extensions that can be used in mail exports. An interesting side note here is that the PST file write does in fact still work, but you can no longer control the file extension.

What this means is that the SSRF is still alive and well, however it’s now hitting the backend unauthenticated! I didn’t have a sample at the time, but made a bit of wild speculation that this was likely the candidate for the ITW exploit.

<center>
<blockquote class="twitter-tweet" data-lang="en">
    <a href="https://twitter.com/buffaloverflow/status/1575756381650493440"></a>
</blockquote>
</center>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

Other vulnerabilities notwithstanding, there are two ways in which an attacker could still abuse this:

-   First they could simply send their own authentication. If the attacker has credentials, they could just authenticate with those. At which point they'd be able to hit any backend services that the user-account permissions allow. Either via Windows-authentication (i.e. NTLM), or with tokens.
-   Secondly, they could attack any _unauthenticated_ backend endpoint.

Ignoring the post-auth RCE for now. Let’s have a look at how we can get the SSRF working against PowerShell again.

If we take the ProxyShell request of:

```
autodiscover/autodiscover.json?@asdf/powershell/?&Email=autodiscover/autodiscover.json%3f@asdf
```

We can plug that into the [pypsrp](https://github.com/jborean93/pypsrp) library, which provides a Python interface for PowerShell remoting. We’ll set the authentication method to NTLM in the WSMan constructor to prevent the server forcing us to use Kerberos, and finally open a RunspacePool, specifying the `Microsoft.Exchange` configuration name, and running the `Get-Mailbox` cmdlet.

> We have to use `add_cmdlet` here instead of `add_command` or `add_script`. This is because after previous Exchange vulnerabilities, Microsoft has hardened the PowerShell configuration to run in [NoLanguage mode](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_language_modes?view=powershell-7.2).

Let’s fire this and see what happens:

![NTLM Authentication with SSRF and PyPSRP](/public/media/pypsrp-request-1.png)

`[+] Success` - it works! We've confirmed that we can indeed hit the PowerShell backend via the ProxyShell SSRF, if we provide our own NTLM authentication.

Ok, so we’re running as a low-privileged user here. Whilst low-privileged users _do_ have access to run PowerShell cmdlets. Their access is limited to a subset of cmdlets, which generally match the functionality available to the user through ECP/OWA. I wrote a quick script to attempt to enumerate a list of available cmdlets. (Caveat: this might not be a complete list, but) [this is what I came up with](https://gist.github.com/rxwx/47cd64b31241a9a487ebe1a255e90637).

As you can see there’s still quite a few cmdlets listed there, and some such as [Get-App](https://learn.microsoft.com/en-us/powershell/module/exchange/get-app?view=exchange-ps) sound quite interesting. However, I had a quick look, didn’t find anything obvious and decided to move on. Perhaps someone did manage to get RCE via one of these cmdlets directly? Perhaps we'll cover this is future post :D

To summarise, we can hit the backend with our own supplied credentials, and we can execute a subset of cmdlets, but what about running cmdlets as a high privileged user?

This got me thinking - the server accepts NTLM on the backend (we skip the frontend constraint due to SSRF), so what about NTLM relay?

If we can coerce authentication from another Exchange server and relay the machine account NTLM authentication via the SSRF, we should be back with a primitive similar to the original ProxyShell vulnerability!

**First, some important credits:**

I’d recollected that something similar had been mentioned by Yuhao Weng and Zhiniang Peng in their “Exploit Exchange in new Ways” [Zer0con](https://twitter.com/POC_Crew/status/1517022633493430272) talk. However, as far as I’m aware, the full slides were never published.

They mentioned [CVE-2021–33768](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-33768), and ProxyRelay in their talk. If we check the patch notes for CVE-2021–33768, this was credited to [Orange Tsai](https://twitter.com/orange_8361) and [Dlive](https://twitter.com/D1iv3). In fact, Orange finally released the [blog post for ProxyRelay](https://devco.re/blog/2022/10/19/a-new-attack-surface-on-MS-exchange-part-4-ProxyRelay/) in October 2022, not long after I started this research, so it was very helpful! It's fantastic research and I suggest if you haven't read it yet you should go and read it!

In the Zer0con talk they also mentioned [CVE-2021–26427](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2021-26427), which was a BinaryFormatter deserialization vulnerability in the DAG replication service running on TCP port 64327 — also using the NTLM relay technique! Checking the patch notes on this one, it was credited to MSRC and the NSA.

Ok, back to NTLM relay ..

#### NTLM Authentication

To test whether the server will accept NTLM relay, we’ll first do a very quick test to see if we can authenticate with the machine account of Exchange. Since we don’t know the plaintext password of the Exchange server, we’ll cheat here and use Pass-the-Hash (you can dump the server's hash using mimikatz' `sekurlsa::msv` module).

Thankfully the [pyspnego](https://github.com/jborean93/pyspnego) module, which is used by pypsrp, has [support](https://github.com/jborean93/pypsrp/issues/77) for pass-the-hash - so we can simply modify our previous test-case to pass in the Exchange server machine account hash:


![Pass-the-Hash Failure](/public/media/pypsrp-request-2.png)

Hmm, it seems to fail with the message:

```
The operation couldn’t be performed because ‘VULNCORP\EXCHANGE2$’ couldn’t be found
```

That’s a bit of a cryptic message. Let’s fire up Burp on the Exchange backend and see what’s happening:

![Exchange Backend Error](/public/media/exchange-backend-error.png)

Indeed it shows that same error in the Receive message. It also shows the failure category `AuthZ-CmdletAccessDeniedException`.

If we take a step back and look at the WSMan Create message response, we can see that a RunSpace Pool was successfully created for the `EXCHANGE2$` user:

![WSMan Create Request and Response](/public/media/wsman-create-request.png)

So we _are_ authenticating successfully with the machine account, it just doesn’t have any cmdlet permissions!

So you may be thinking that this is bad news. Surely if we perform an NTLM relay attack, we’re not going to be able to actually execute any cmdlets? It certainly seems so, but before we give up let’s go back to ProxyShell..

#### Privilege De-escalation

If you remember from Orange’s writeup, they were able to abuse another vulnerability, [CVE-2021–34523](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34523) to effectively “downgrade” the machine account SYSTEM context to that of an administrative domain user.

![Extract from ProxyShell blog showing X-Rps-CAT Privilege Escalation Technique](/public/media/ProxyShell-blog-X-Rps-CAT.png)

So prior to CVE-2021-34523, it was possible to impersonate any user by sending an `X-Rps-CAT` parameter in the query string with a forged `CommonAccessToken`. Let’s have a look again at the code for handling `X-Rps-CAT`:

![OnAuthenticateRequest Source Code](/public/media/OnAuthenticateRequest.png)

This code looks very similar to how it was before (if not identical). So why can we not just do the same thing? If we examine the code, the first thing it does is check if there is already an `X-CommonAccessToken` header set in the backend request. If we go and check in burp we can see that the frontend already inserted an `X-CommonAccessToken` header into the proxied request, so the backend will never attempt to use the `X-Rps-CAT` token.

![Frontend Request to Backend Containing X-CommonAccessToken ](/public/media/Frontend-X-CommonAccessToken.png)

To verify our understanding, let's modify a request sent from the Frontend to the Backend, by removing the `X-CommonAccessToken` header and inserting a forged `X-Rps-CAT` token in the URL. To make things clear, I’ve forged the token to contain the fake username `VULCORP\impacket`. As shown in the following screenshot, simply by removing the `X-CommonAccessToken` header, we are able to use `X-Rps-CAT` again!

![Forged Token Accepted](/public/media/X-RPS-Cat-working.png)

Now we know how and why the the old `X-Rps-CAT` elevation of privilege can’t be used now, since we have no control over the Frontend adding the `X-CommonAccessToken` header.. but do we? What about if we supply our own header? Let’s look at the code.

In `ProxyRequestHandler.cs`, in the `AddProtocolSpecificHeadersToServerRequest` function we can see the following code. This code is executed on the Frontend. First it checks if the request is authenticated and if the request headers contain the `X-CommonAccessToken` header. If so, it will attempt to deserialize the token. If this token turns out to be a `SYSTEM` or Machine account, it raises a 400 error.

After this, it checks the identity of the calling user (i.e. the user that authenticated in the Frontend HTTP request). If the user is _not_ `SYSTEM` or a Machine account, it also bails with a 400 error.

![AddProtocolSpecificHeadersToServerRequest Function](/public/media/AddProtocolSpecificHeadersToServerRequest.png)

What do the `IsSystemOrMachineAccount` and `IsSystemOrTrustedMachineAccount` functions actually do? (despite their names making it fairly obvious!).

-   `IsSystemOrMachineAccount` — simply checks if some properties of the deserialized access token match that of a `SYSTEM` or Machine account, e.g. the SID is the well-known SID of `SYSTEM`, the account name ends with `$` or the `LogonName` is 0.
-   `IsSystemOrTrustedMachineAccount` — Checks whether the `IsSystem` property of the WindowsIdentity is set to true OR if the Identity name ends with `$` AND the identity has the `ms-Exch-EPI-Token-Serialization` extended right in AD.

If both checks are passed (i.e. the `X-CommonAccessToken` token is _not_ for a machine account, but the caller _is_ a machine account), it will go ahead and forward the token to the backend. Bingo! We can pass both checks because:

-   We can specify whatever we want in the token because there are no integrity checks (even make up the user-account name as long as the SID is correct).
-   We will be connecting under the context of the (relayed) machine account from another Exchange server. Exchange servers by default have the `ms-Exch-EPI-Token-Serialization` extended right.

#### Putting it All Together

So putting it all together we need to:

-   Trigger authentication on a second Exchange server (lets call it `EXCHANGE1`).
-   Relay the authentication to `EXCHANGE2`, but set our own `X-CommonAccessToken` header, containing a forged token for any user on the domain (e.g. a Domain Administrator).
-   Open a PowerShell session, and execute any cmdlet.

But before we do this, we’ll need to collect some pre-requisites. You may remember from the ProxyShell exploit that we’ll need to gather some information that we’ll use later to forge the token. For example, we’ll need to collect:

-   The hostname and FQDN of the server — this can be leaked from the `X-FEServer`, `X-BEServer` and `X-CalculatedBETarget` response headers from `/autodiscover/autodiscover/json`
-   Optionally, we might need to Legacy DN, which we can get from Autodiscover. This is only really needed if we’re using the `/mapi/emsmdb` SID leaking technique from ProxyLogon.
-   The SID of the user we want to impersonate. Again we can leak this from MAPI — either using the `/mapi/emsmdb` technique used in ProxyLogon, or simply making an authenticated request to `/mapi/nspi`.

An interesting thing to note here is that just like ProxyShell, the SSRF _is not limited_ to only the `/powershell` endpoint. You can hit any backend service with it, especially if you’re providing the (relayed) auth. For example, you could hit EWS on the backend, and impersonate any user thanks to our `SYSTEM` context. This makes it very convenient to gather all the info we need - but also worth noting because the Microsoft mitigations only target the `/powershell` endpoint.

Let’s try that. For example, we could target EWS. In the below example, I sent relayed NTLM authentication via the SSRF to the EWS backend. In the request we can impersonate any user, simply by specifying their SID. For this demo, I impersonated the Domain Admin. In the ProxyShell chain, this trick was used to save a draft email in a user's inbox (which was later exported via PowerShell, for RCE) - but you could do lots of other things, such as send an email, or exploit [CVE-2021-42321](https://peterjson.medium.com/some-notes-about-microsoft-exchange-deserialization-rce-cve-2021-42321-110d04e8852)!

![EWS Request](/public/media/ews-ssrf.png)

![Draft Email Successfully Saved via ProxyNotRelay](/public/media/draft-email.png)


## Mitigations

### IIS Rewrite

When the ProxyNotShell advisory was first released by Microsoft, they also pushed out an IIS rewrite rule via the [Exchange Emergency Mitigation Service](https://learn.microsoft.com/en-us/exchange/exchange-emergency-mitigation-service?view=exchserver-2019). This is a service that runs on Exchange 2016 and 2019 servers with the November 2021 SU and later. The idea is that if a security issue is identified, Microsoft can quickly push out mitigations to supported Exchange servers worldwide. It works pretty well as long as you are on a supported SU. For those that aren’t on a supported SU, or can’t use EEMS — they also provided a mitigation via the EOMTv2 PowerShell script, which implements the same IIS rewrite rule, as well as instructions on how to apply the rewrite rule manually.

The problem is, the rewrite rule didn’t take into account a number of scenarios, leading to multiple bypasses being discovered:

-   Firstly, [Jang discovered](https://twitter.com/testanull/status/1576774007826718720) that Microsoft Exchange’s own code allowed for the substitution of the @ symbol with .. in the URL which bypassed the regex used.
-   Microsoft released a second iteration of the rewrite rule, this was [bypassed again](https://twitter.com/honoki/status/1577644964628004867) using URL encoding.
-   Another iteration of the IIS rule was released, but unfortunately this was also [bypassable](https://twitter.com/GossiTheDog/status/1578522829963767809), as it was possible to specify the _powershell_ portion of the URL _prior_ to _/autodiscover.json_ (not aware of a PoC for this).

We’re now currently on the following rewrite rule — at the time of publishing:

![Latest IIS URL Rewrite Mitigation](/public/media/latest-rewrite-mitigation.png)

#### x-up-devcap-post-charset bypass

As shown above, Microsoft implemented an IIS rewrite rule which now decodes the request URI using `UrlDecode`. However as [Soroush Dalili](https://twitter.com/irsdl/) pointed out in a [Twitter thread](https://twitter.com/irsdl/status/1581388036046487552), and several interesting [blog](https://www.mdsec.co.uk/2021/09/nsa-meeting-proposal-for-proxyshell/) [posts](https://soroush.secproject.com/blog/2019/05/x-up-devcap-post-charset-header-in-aspnet-to-bypass-wafs-again/) - this is still pretty fragile, and can be bypassed using the `x-up-devcap-post-charset` header to supply an alternative charset and hide the real URL!

<center>
<blockquote class="twitter-tweet" data-lang="en">
    <a href="https://twitter.com/irsdl/status/1581388036046487552"></a>
</blockquote>
</center>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

With a few tweaks can add this to our `ntlmrelayx` module to bypass the IIS rewrite mitigation!

![IBM 500 Encoding with Python](/public/media/ibm500-encoding-python.png)

### ProxyRelay Mitigations

In late October 2022, Orange released a [detailed blog post](https://devco.re/blog/2022/10/19/a-new-attack-surface-on-MS-exchange-part-4-ProxyRelay/) on the ProxyRelay issues. It turns out that despite reporting the issue back in June 2021, the full fix was not enabled completely until August 2022, and even then it required *manual intervention* to enable.

#### Extended Protection

In terms of fixing ProxyRelay, Microsoft first released an update to support Extended Protection in the Microsoft Exchange CU in April 2022. However the feature wasn’t enabled until the August SU, when the [documentation was published](https://techcommunity.microsoft.com/t5/exchange-team-blog/released-august-2022-exchange-server-security-updates/ba-p/3593862) detailing the mitigation steps required, as well as the CVE. It should be noted that this requires manual steps despite the words “enabled in the August SU”, you have to actually go and run a script or manually activate Extended Protection in Exchange/IIS to get the benefit. I’m not sure if this is something that everyone will do, despite Microsoft’s efforts to document it.

#### How does this Mitigation Work?

This mitigation makes use of [Windows Extended Protection](https://learn.microsoft.com/en-us/iis/configuration/system.webserver/security/authentication/windowsauthentication/extendedprotection/), which aims to prevent MITM and Relay attacks by utilising Channel Binding Tokens in TLS connections to bind the authentication to a channel (i.e. TLS connection), as described in [RFC 5929](https://www.rfc-editor.org/rfc/rfc5929) and [RFC5056](https://www.rfc-editor.org/rfc/rfc5056).

> Extended Protection for Authentication (EPA) has actually been around for a while and is supported [since Windows Vista](https://msrc-blog.microsoft.com/2009/12/08/extended-protection-for-authentication/). and is already used for hardening WinRM. Perhaps I’ll revisit this another day.

The way the CBT checking works, in simple terms is like this:

-   First the client makes a TLS connection to the server, and hashes the server’s certificate.
-   In the authentication message (i.e. NTLM), it sends this hash to the server. This is the Channel Binding Token.
-   Now the server can check this token and see if the certificate hash matches that of the server.
-   If not then the request has either been modified since the client generated the authentication message OR the authentication message was not generated for this server (i.e. it was generated for a MITM server).

So at a high-level, if a client is coerced to send an authentication message to a rogue server, that rogue server would not be able to replay that authentication message, since the CBT will contain the hash of the attacker’s server and _not_ the target server.

But surely an attacker could just remove the CBT before forwarding it onto the target server? (Un)forunately not. This data is protected by the `NTProofStr` and so cannot be tampered with without knowing the user’s password.

What about if the client doesn't support Channel Binding and thus never sends CBT data in the first place? Well in this case, the server can be configured in three modes:

* `Off` - No Extended Protection is enabled. Whether the client sends a CBT or not, it is ignored. 
* `Accept` - IIS will accept clients that support CBT and will perform checks, however if the client does not support EPA, requests will still be accepted.
* `Required` - IIS enforces CBT checking. If the client doesn't send CBT data, the request is denied.

If you'd like to know more about CBT, SPNs and how they affect NTLM relaying, I highly recommend [this article](https://en.hackndo.com/ntlm-relay/) by [@HackAndDo](https://twitter.com/HackAndDo), which explains the concepts better than I could.

To verify my understanding. I made this [quick script](https://gist.github.com/rxwx/8476acf1f2ca8727c8d356ea26291354)), which just hooks the `ntlm-auth` and `requests-ntlm` Python modules so that we can dump out the CBT data. Using this we can see that when using CBT, the MD5 hash of the server's certificate is sent in the NTLM auth data.

![Dumping CBT Data from NTLM Auth Request with Python](/public/media/cbt-data-dump.png)

So now we know a little bit about EPA and CBT, let's have a look at how this is implemented in Microsoft Exchange. According to the [Microsoft CSS-Exchange documentation](https://microsoft.github.io/CSS-Exchange/Security/Extended-Protection/), to enable Extended Protection, you need to run the `ExchangeExtendedProtectionManagement.ps1` script.

There are some pre-requisites to enable first, but once you've run the script it should deploy the *recommended* configuration for Exchange.

So now we've enabled Extended Protection. Let's have a look at the configuration with `ExchangeExtendedProtectionManagement.ps1 -ShowExtendedProtection`:

![EPA Default Settings](/public/media/epa-settings.png)

Looking at the above we can see that Extended Protection is set to `Require` for many of the Frontend and Backend services. For example MAPI is set to `Require`, meaning that CBT checks should always be enforced. Let's do a quick test with and without CBT to verify our understanding:

![Requesting MAPI with and without CBT](/public/media/epa-mapi-test.png)

Nice! So far so good. However, if we look at Autodiscover, we can see it's set to `None`! 😲
Why is this bad? Well, due to the the specifc exclusion for Autodiscover, it allows us to relay to *any* service (that supports NTLM), since our SSRF requests always come via Autodiscover, regardless of the real destination!

## EPA for EWS

Additionally, as EWS and ActiveSync are currently still set to `Allow` (equivalent of `Accept` in the previous description) - this means that if we're relaying from SMB, there will never be any CBT data sent by the client and relaying to those services might still be possible. However for ActiveSync this is unlikely since the [default authentication method is Basic](https://learn.microsoft.com/en-us/exchange/clients/default-virtual-directory-settings?view=exchserver-2019). Let's verify that quickly with EWS, by sending a request without CBT:

![Sending NTLM authentication to EWS with no CBT](/public/media/ews-no-cbt.png)

It worked! But when we try it with a modified `ntlmrelayx.py` we get this:

![Failed to Relay to EWS](/public/media/ews-relay-fail.png)

I was racking my brains for a long time trying to figure out why this did not work. But then I remembered that this was one of the examples shown in Orange's [ProxyRelay blog](https://devco.re/blog/2022/10/19/a-new-attack-surface-on-MS-exchange-part-4-ProxyRelay/)!

![Patch Details for CVE-2021-33768 from DEVCORE Blog](/public/media/proxyrelay-blog.png)

Indeed if we look at the new code, they changed the check inside `ProxyRequestHandler::AddProtocolSpecificHeadersToServerRequest` to replace `IsSytemOrMachineAccount` with `IsSystemAccount`, meaning that it will no longer generate an `X-CommonAccessToken` for the foreign Machine account and instead will raise a 400 error.

![IsSystemAccount Diff](/public/media/IsSystemAccount-diff.png)

Actually there's been several changes since June 2021. Including this curious change where instead of comparing the `CommonAccess.TokenType` of `Windows` to the string `Windows`, they now compare it with the literal string of "0".

![Diff Showing September 2021 Bug](/public/media/sept-21-access-token-type.png)

Yet, despite these changes, I still could not get it to hit `AddProtocolSpecificHeadersToServerRequest` in the debugger. It seemed to fail at the IIS authentication level during Windows Authentication, even when the Extended Protection setting was set to `Accept`. I need to do some more investigation here, but while i was writing this, the patches got released - so I'll probably have to come back to this another time.

## EPA Bypass for Autodiscover

So ActiveSync is not attackable in a default configuration, and EWS has been patched to prevent easy relaying. That just leaves the Autodiscover Frontend endpoint!

To summarise, Extended Protection does not currently protect against NTLM relaying to the `/autodiscover` endpoint and is not required for ActiveSync or EWS. So if the server is vulnerable to ProxyNotShell (CVE-2022–41040), it allows for a complete bypass of Extended Protection via Autodiscover.

### Automating with Impacket

Now that we have a strategy for relaying NTLM between two Exchange servers, a bypass for the IIS URL rewrite and a bypass of Extended Protection, let's wrap it up in an `ntmlrelayx` module and take it for a spin!

To achieve this I had to port `pypsrp` and `requests` into impacket's `ntlmrelayx.py`, which involved creating a custom `requests` adapter where I could supply the relayed TCP socket, and also override some functionality in `pypsrp`, `requests` and `urllib` to support sending raw bytes in the HTTP request. I won't go into the boring details here, but will release the code once folks have had a chance to install the patch.

**Update**: Proof of Concept is available [here](https://github.com/rxwx/impacket).

Now we can run `ntlmrelayx.py` with the new `--exchange-powershell` module and the `--bypass` flag and we should get some output from `Get-Mailbox` cmdlet, running as Domain Admin!

<div style="padding:50.68% 0 0 0;position:relative;"><iframe src="https://player.vimeo.com/video/763582788?h=9b82dc4491&amp;badge=0&amp;autopause=0&amp;player_id=0&amp;app_id=58479" frameborder="0" allow="autoplay; fullscreen; picture-in-picture" allowfullscreen style="position:absolute;top:0;left:0;width:100%;height:100%;" title="proxynotshell-relay.mov"></iframe></div><script src="https://player.vimeo.com/api/player.js"></script>

#### Antimalware Scan Interface (AMSI)

Just when I thought that all the mitigations could be bypassed, [Jang](https://twitter.com/testanull) messaged me to say that he couldn’t get it working with the IBM500 encoding trick. After some testing he confirmed this was due to AMSI blocking the request.

Indeed, when I enabled Defender in my test environment, it did block the request!

![AMSI Alert](/public/media/amsi-alert.png)

In June 2021 [Microsoft added support](https://techcommunity.microsoft.com/t5/exchange-team-blog/more-about-amsi-integration-with-exchange-server/ba-p/2572371) for the Antimalware Scan Interface (AMSI) into Microsoft Exchange 2016 and 2019.

This feature works by adding an `HttpRequestFilteringModule` DLL into the `web.config`:

![Autodiscover web.config file](/public/media/autodiscover-web-config.png)

If we decompile this DLL we can see that adds a `BeginRequest` event handler, which calls into `OnBeginRequestInternal`.

![OnBeginRequestInternal.png](/public/media/OnBeginRequestInternal.png)

This method passes the HTTP request to `AmsiScanRequest`, which in turn flattens the HTTP request data and passes it to `AmsiScanBuffer`. If AMSI detects malicious content, then the server will return a 400 status code.

Interestingly, the `AmsiScanRequest` code attempts to mask PII (email addresses), however this doesn't appear to be exploitable for any bypass since this only affects the `contentName` parameter and not the `buffer` that is scanned by AMSI.

![AmsiScanRequest](/public/media/amsi-scan-request.png)

Once I'd understood how requests were being scanned. I created a basic standalone AMSI client which replicated the code used by Exchange, and also dumped a sample buffer from `AmsiScanRequest`, so that I could attempt to minimise the signature.

![Dumped AMSI Buffer](/public/media/amsi-buffer.png)

After a few tests, I came up with the following minmised signature. It simply checks for any occurrance of the word `powershell` *after* `/autodiscover.json`. 

![Minmised AMSI Testcase](/public/media/amsi-minimised.png)

A couple of things I noted was that any occurance of `:` before the word `powershell` would break the signature, as this appears to be used to delimit headers. Additionally, any character other than `/` before `autodiscover` will also break the signature. However, I was not able to craft a request which satisfied either of these requirements.

I also had another idea. What about if we could construct an HTTP request which used the SSRF against the Frontend to construct a second SSRF targeting the backend. Whilst this bypasses AMSI on the Frontend, it still triggered on the Backend with a 400 status.

![Double SSRF Attack](/public/media/double-ssrf.png)

So after some limited testing I came to the conclusion that AMSI is the best mitigation (and possibly the only working one) against the ProxyNotRelay attack - other than patching of course! However it does require that you are either running Microsoft Defender or at least an AV with AMSI support. Additionally, as I demonstrated earlier, this only protects against attacks targeting the `/powershell` backend, so worth bearing in mind.

### An Alternative IIS Rewrite Approach

I had this idea, which I posted in a [Twitter thread](https://twitter.com/buffaloverflow/status/1581690003339767808). Instead of trying to rewrite IIS requests on the Frontend, why not do it on the backend instead? That way we have more control of the data, and can process things like headers that are sent by the Frontend, for example.

The idea is basically that instead of trying to block-list bad requests, we can instead allow-list based on the `msExchProxyUri` which is sent by the Frontend.

The concept is that the Frontend will send the URL that was visited on the Frontend in this header and send it to the Backend. If we set an IIS rewrite rule on the Backend to detect when the Frontend URI is different from the Backend, we can detect SSRF and block the request. This works because, for example, a request to `/autodiscover/autodiscover.json` on the Frontend would send a header like:

```
msExchProxyUri: https://exchange.corp.local/autodiscover/autodiscover.json
```

So if we write an IIS rewrite rule on the Backend `/powershell` Virtual Directory, which denies anything that doesn't start with `<url>/powershell` then we can create an effective SSRF protection without worrying about request encoding.

The caveat is that I haven't tried this in a production environment, so YMMV!

![IIS Backend Rewrite](/public/media/backend-rewrite.jpg)

_Note 09/11/22 - Indeed it seems like MS implemented something similar to this directly within Exchange to detect cross Virtual Directory requests_.

### The Patches

I originally started writing this post before the patches were released, but these were finally released by Microsoft on the 8th November 2022, so instead of worrying about mitigations, go ahead and install the official patches instead!

* https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41082
* https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41040

I'll do a follow-up post on the patch diffing and RCE write-up ;)

`e756b455fc01d6a9bfe9b1f4382969db`

### **Future Attacks**

Orange already alluded to this but IIS (web) services isn’t the only network accessible services exposed by Exchange. We’ve already seen a relay attack demonstrated against DAG. I think there will be more vulnerabilities like this in the future.

