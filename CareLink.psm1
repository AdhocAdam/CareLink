<#
.SYNOPSIS
A PowerShell Module to interact with Minimed CareLink
.DESCRIPTION
This PowerShell module emulates browser interaction to Minimed CareLink to retrieve a patient's blood glucose data
#>

function Get-CareLinkToken {
  <#
      param (
        #The Carelink username
        [parameter(ParameterSetName = 'ManualCred', Mandatory = $true, Position = 0)]
        [string]$username,
        #The Carelink password
        [parameter(ParameterSetName = 'ManualCred', Mandatory = $true, Position = 1)]
        [string]$password,
        #PowerShell credential object that contains username/password
        [parameter(ParameterSetName = 'PSCredential', Mandatory = $true, Position = 2)]
        [PSCredential]$Credential,
        #Browser to impersonate,
        [parameter(Mandatory = $false, Position = 3)]
        [ValidateSet("InternetExplorer", "Firefox", "Chrome", "Opera", "Safari")]
        [string]$BrowserName="Chrome"
    )

    #login page
    $loginPage = "https://carelink.minimed.com/patient/sso/login?country=us&lang=en"
    $login = Invoke-WebRequest -Uri $loginPage -UserAgent $userAgent -UseBasicParsing -SessionVariable medtronic
    $sessionID = ($login.InputFields | Where-Object { $_.name -eq "sessionID" }).Value
    $sessionDataOne = ($login.InputFields | Where-Object { $_.name -eq "sessionData" }).Value

    #define the user agent string
    $userAgentList = [Microsoft.PowerShell.Commands.PSUserAgent].GetProperties() | Select-Object Name, @{Name = 'UserAgent'; Expression = { [Microsoft.PowerShell.Commands.PSUserAgent]::$($_.Name) } }
    $userAgent = $userAgentList | Where-Object { $_.Name -eq $BrowserName }

    #if the credentials came in via PSCredentialObject, copy them to update variable names to be used later
    if ($PsCmdlet.ParameterSetName -eq "PSCredential")
    {
        $username = $credential.UserName
        $password = $credential.GetNetworkCredential().Password
    }

    #login to carelink
    $loginBody = @{
        "sessionID"    = $sessionID
        "sessionData"  = $sessionDataOne
        "locale"       = "en"
        "action"       = "login"
        "actionButton" = "Log in"
        "username"     = $username
        "password"     = $password
    }
    $loginResponse = Invoke-WebRequest -Uri "https://mdtlogin.medtronic.com/mmcl/auth/oauth/v2/authorize/login" -Body $loginBody -Method "POST" -UserAgent $userAgent -ContentType "application/x-www-form-urlencoded" -UseBasicParsing -WebSession $medtronic

    #since we're using basic parsing in the above call to avoid the Internet Explorer dependency, we need to convert the response's Content to HTML to fish out the sessionData value
    $loginResponseHTML = New-Object -comobject "HTMLFile"
    $loginResponseBytes = [System.Text.Encoding]::Unicode.GetBytes($loginResponse.content)
    $loginResponseHTML.write($loginResponseBytes)
    $sessionDataTwo = $loginResponseHTML.getElementById("sessionData").value

    #consent, use the sessionId and sessionData from the login response
    $consentBody = @{
        "action"        = "consent"
        "response_mode" = "query"
        "response_type" = "code"
        "sessionID"     = $sessionId
        "sessionData"   = $sessionDataTwo
    }
    $consentPageResponse = Invoke-WebRequest -Uri "https://mdtlogin.medtronic.com/mmcl/auth/oauth/v2/authorize/consent" -Body $consentBody -Method "POST" -UserAgent $userAgent -ContentType "application/x-www-form-urlencoded" -UseBasicParsing -WebSession $medtronic

    #get the auth token and its expiration date from the cookies in the $medtronic websession
    $authTmpToken = $medtronic.cookies.GetCookies("https://carelink.minimed.com") | Where-Object { $_.Name -eq "auth_tmp_token" }
    $cTokenValidTo = $medtronic.cookies.GetCookies("https://carelink.minimed.com") | Where-Object { $_.Name -eq "c_token_valid_to" }

    #turn into a PSCustomObject for subsequent use
    $token = [PSCustomObject] @{
        Token           = $authTmpToken
        TokenExpiration = $cTokenValidTo
        Websession      = $medtronic
        UserAgent       = $userAgent
        username        = $username
        password        = $password
    }

    return $token
    #>

  if ($script:CarelinkToken) {
    return $script:CarelinkToken
  }
  else {
    return "Token has not been declared. Use Set-CareLinkToken to define it"
  }
}

#retrieve user account information such as their Login Date, Account ID, and User Role
function Get-CareLinkAccount {
    param (
        #The Carelink username
        [parameter(Mandatory = $true, Position = 0)]
        [PSCustomObject]$Token
    )

    #verify the token is still valid before proceding
    $token = Confirm-CarelinkToken -Token $token

    $authHeader = @{
        "Accept"          = "application/json, text/plain, */*"
        "Accept-Encoding" = "gzip, deflate, br"
        "Accept-Language" = "en-US,en;q=0.6"
        "Authorization"   = "Bearer $($Token.Token.value)"
        "Referer"         = "https://carelink.minimed.com/app/home"
        "Sec-Fetch-Dest"  = "empty"
        "Sec-Fetch-Mode"  = "cors"
        "Sec-Fetch-Site"  = "same-origin"
        "Sec-GPC"         = "1"
      }

    #call the Me rest endpoint
    $me = Invoke-RestMethod -Uri "https://carelink.minimed.com/patient/users/me" -Method "GET" -header $authHeader -UserAgent $token.userAgent -WebSession $token.websession
    return $me
}

#retrieve user profile information, username, phone number, etc.
function Get-CareLinkProfile {
    param (
        #The Carelink username
        [parameter(Mandatory = $true, Position = 0)]
        [PSCustomObject]$Token
    )

    #verify the token is still valid before proceding
    $token = Confirm-CarelinkToken -Token $token

    $authHeader = @{
        "Accept"          = "application/json, text/plain, */*"
        "Accept-Encoding" = "gzip, deflate, br"
        "Accept-Language" = "en-US,en;q=0.6"
        "Authorization"   = "Bearer $($Token.Token.value)"
        "Referer"         = "https://carelink.minimed.com/app/home"
        "Sec-Fetch-Dest"  = "empty"
        "Sec-Fetch-Mode"  = "cors"
        "Sec-Fetch-Site"  = "same-origin"
        "Sec-GPC"         = "1"
      }

    #call the Me rest endpoint
    $me = Invoke-RestMethod -Uri "https://carelink.minimed.com/patient/users/me/profile" -Method "GET" -header $authHeader -UserAgent $token.userAgent -WebSession $token.websession
    return $me
}

function Get-CareLinkData {
    param (
        #The Carelink username
        [parameter(Mandatory = $true, Position = 0)]
        [PSCustomObject]$Token,
        #The Carelink Account User
        [parameter(Mandatory = $true, Position = 1)]
        [PSCustomObject]$CarelinkUserProfile,
        #The Carelink User's Profile
        [parameter(Mandatory = $true, Position = 2)]
        [PSCustomObject]$CarelinkUserAccount
    )

    #verify the token is still valid before proceding
    $token = Confirm-CarelinkToken -Token $token

    #authentication header to make the request
    $authHeader = @{
        "Accept"          = "application/json, text/plain, */*"
        "Accept-Encoding" = "gzip, deflate, br"
        "Accept-Language" = "en-US,en;q=0.6"
        "Authorization"   = "Bearer $($Token.Token.value)"
        "Referer"         = "https://carelink.minimed.com/app/home"
        "Sec-Fetch-Dest"  = "empty"
        "Sec-Fetch-Mode"  = "cors"
        "Sec-Fetch-Site"  = "same-origin"
        "Sec-GPC"         = "1"
      }

    #pump, sensor, and glucose
    $payload = @{
        "username" = $CarelinkUserProfile.username
        "role"     = $CarelinkUserAccount.role
    } | ConvertTo-Json

  $data = Invoke-RestMethod -Uri "https://clcloud.minimed.com/connect/v2/display/message" -Method "POST" -body $payload -header $authHeader -UserAgent $token.userAgent -WebSession $token.websession
  return $data
}

function Confirm-CareLinkToken {
    param (
        #The Carelink token to validate
        [parameter(Mandatory = $true, Position = 0)]
        [PSCustomObject]$Token
    )

    #convert the token expiration string to a datetime object to compare
    #string/datetime conversion, https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-powershell-1.0/ee692801(v=technet.10)?redirectedfrom=MSDN
    $expiration = [datetime]::ParseExact($token.TokenExpiration.Value.Split("UTC")[0].Trim(), "ddd MMM dd HH:mm:ss", $null)
    $nowUTC = (Get-Date).ToUniversalTime()

    #compare the expiration date to now
    if ($nowUTC -gt $expiration)
    {
        Write-Output "Token expired. Renewing..."
        $newToken = Get-CareLinkToken -username $token.username -password $token.password
        return $newToken
    }
    else
    {
        Write-Output "Token valid"
        return $token
    }
}
