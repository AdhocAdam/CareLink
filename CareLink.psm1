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
  <#
  param (
    #The Carelink username
    [parameter(Mandatory = $true, Position = 0)]
    [PSCustomObject]$Token
  )
  #>

  if ($script:CareLinkToken) {
    #verify the token is still valid before proceding
    $token = Confirm-CarelinkToken

    $authHeader = @{
      "Accept"          = "application/json, text/plain, */*"
      "Accept-Encoding" = "gzip, deflate, br"
      "Accept-Language" = "en-US,en;q=0.6"
      "Authorization"   = "Bearer $($script:CareLinkToken.token)"
      "Referer"         = "https://carelink.minimed.com/app/home"
      "Sec-Fetch-Dest"  = "empty"
      "Sec-Fetch-Mode"  = "cors"
      "Sec-Fetch-Site"  = "same-origin"
      "Sec-GPC"         = "1"
    }

    #call the Me rest endpoint
    $me = Invoke-RestMethod -Uri "https://carelink.minimed.com/patient/users/me" -Method "GET" -header $authHeader -UserAgent $token.userAgent #-WebSession $token.websession
    return $me
  }
  else {
    Write-Error "Token is not defined. Please retrieve a token, expiration date, and then set it with Set-CareLinkToken"
  }
}

#retrieve user profile information, username, phone number, etc.
function Get-CareLinkProfile {
  <#
  param (
    #The Carelink username
    [parameter(Mandatory = $true, Position = 0)]
    [PSCustomObject]$Token
  )
  #>

  if ($script:CareLinkToken) {
    #verify the token is still valid before proceding
    $token = Confirm-CarelinkToken

    $authHeader = @{
      "Accept"          = "application/json, text/plain, */*"
      "Accept-Encoding" = "gzip, deflate, br"
      "Accept-Language" = "en-US,en;q=0.6"
      "Authorization"   = "Bearer $($script:CareLinkToken.token)"
      "Referer"         = "https://carelink.minimed.com/app/home"
      "Sec-Fetch-Dest"  = "empty"
      "Sec-Fetch-Mode"  = "cors"
      "Sec-Fetch-Site"  = "same-origin"
      "Sec-GPC"         = "1"
    }

    #call the Me rest endpoint
    $me = Invoke-RestMethod -Uri "https://carelink.minimed.com/patient/users/me/profile" -Method "GET" -header $authHeader -UserAgent $token.userAgent #-WebSession $token.websession
    return $me
  }
  else {
    Write-Error "Token is not defined. Please retrieve a token, expiration date, and then set it with Set-CareLinkToken"
  }
}

function Get-CareLinkData {
  <#
    .SYNOPSIS
        Retrieve's a patient's insulin pump information, blood glucose, etc.
    .DESCRIPTION
        Used to retrieve information about a patient's insulin pump, blood glucose, active alerts, and other information as reported
    .EXAMPLE
        $clAccount = Get-CareLinkAccount
        $clProfile = Get-CareLinkProfile
        $data = Get-CareLinkData -CarelinkUserProfile $clProfile -CarelinkUserAccount $clAccount
        $data
  #>

  param (
    <#The Carelink username
    [parameter(Mandatory = $true, Position = 0)]
    [PSCustomObject]$Token,
    #>
    #The Carelink Account User
    [parameter(Mandatory = $true, Position = 1)]
    [PSCustomObject]$CarelinkUserProfile,
    #The Carelink User's Profile
    [parameter(Mandatory = $true, Position = 2)]
    [PSCustomObject]$CarelinkUserAccount
  )

  if ($script:CareLinkToken) {
    #verify the token is still valid before proceding
    $token = Confirm-CarelinkToken

    #authentication header to make the request
    $authHeader = @{
      "Accept"          = "application/json, text/plain, */*"
      "Accept-Encoding" = "gzip, deflate, br"
      "Accept-Language" = "en-US,en;q=0.6"
      "authorization"   = "Bearer $($script:CareLinkToken.token)"
      "authority"       = "clcloud.minimed.com"
      "path"            = "/connect/carepartner/v6/display/message"
      "origin"          = "https://carelink.minimed.com"
      "referer"         = "https://carelink.minimed.com/"
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

    $data = Invoke-RestMethod -Uri "https://clcloud.minimed.com/connect/carepartner/v6/display/message" -Method "POST" -Body $payload -header $authHeader #-UserAgent $token.userAgent #-WebSession $token.websession
    return $data
  }
  else {
    Write-Error "Token is not defined. Please retrieve a token, expiration date, and then set it with Set-CareLinkToken"
  }
}

function Confirm-CareLinkToken {
  <#
    .SYNOPSIS
        Confirms the Carelink token's validity
    .DESCRIPTION
        Used by other cmdlets within the module to verify the token being used to retrieve data from Carelink is valid. Can be used independently to verify a token's validity.
    .EXAMPLE
        Confirm-CareLinkToken
  #>

  <#
  param (
    #The Carelink token to validate
    [parameter(Mandatory = $true, Position = 0)]
    [PSCustomObject]$Token
  )
  #>

  if ($script:CareLinkToken) {
    #convert the token expiration string to a datetime object to compare
    #string/datetime conversion, https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-powershell-1.0/ee692801(v=technet.10)?redirectedfrom=MSDN
    $expiration = [datetime]::ParseExact($script:CareLinkToken.Expiration.Split("UTC")[0].Trim(), "ddd MMM dd HH:mm:ss", $null)
    $nowUTC = (Get-Date).ToUniversalTime()

    #compare the expiration date to now, by adding a minute we know if we're within expiration
    if ($nowUTC -gt $expiration) {
      Write-Warning "Token expiring. Renewing..."

      #request a new token with the current token
      $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
      $session.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
      $session.Cookies.Add((New-Object System.Net.Cookie("auth_tmp_token", "$($script:CareLinkToken.token)", "/", "carelink.minimed.com")))
      $session.Cookies.Add((New-Object System.Net.Cookie("c_token_valid_to", "$($script:CareLinkToken.expiration)", "/", "carelink.minimed.com")))
      $session.Cookies.Add((New-Object System.Net.Cookie("application_country", "us", "/", "carelink.minimed.com")))
      $session.Cookies.Add((New-Object System.Net.Cookie("application_language", "en", "/", "carelink.minimed.com")))
      $renewedToken = Invoke-WebRequest -UseBasicParsing -ContentType "application/json; charset=UTF-8" -Uri "https://carelink.minimed.com/patient/sso/reauth" `
        -Method "POST" `
        -WebSession $session `
        -Headers @{
        "Accept"             = "application/json, text/plain, */*"
        "Accept-Encoding"    = "gzip, deflate, br"
        "Accept-Language"    = "en-US,en;q=0.9"
        "Authorization"      = "Bearer $($script:CareLinkToken.token)"
        "Origin"             = "https://carelink.minimed.com"
        "Referer"            = "https://carelink.minimed.com/app/connect"
        "Sec-Fetch-Dest"     = "empty"
        "Sec-Fetch-Mode"     = "cors"
        "Sec-Fetch-Site"     = "same-origin"
        "sec-ch-ua"          = "`"Google Chrome`";v=`"119`", `"Chromium`";v=`"119`", `"Not?A_Brand`";v=`"24`""
        "sec-ch-ua-mobile"   = "?0"
        "sec-ch-ua-platform" = "`"Windows`""
      }

      #define token object to return from the Headers in the response
      $updatedToken = [PSCustomObject]@{
        Expiration = ($renewedToken.Headers.'Set-Cookie'.Split(';') | Where-Object { $_.StartsWith("c_token_valid_to") }).Split('=')[1]
        Token      = ($renewedToken.Headers.'Set-Cookie'.Split(';') | Where-Object { $_.StartsWith("auth_tmp_token") }).Split('=')[1]
        Headers    = $renewedToken.Headers
      }

      #update the token used within the module's scope
      Set-CareLinkToken -Expiration $updatedToken.Expiration -Token $updatedToken.Token
    }
    else {
      Write-Output "Token valid"
      return $true
    }
  }
  else {
    Write-Error "Token is not defined. Please retrieve a token, expiration date, and then set it with Set-CareLinkToken"
  }
}

function Set-CareLinkToken {
  <#
    .SYNOPSIS
        Set the Carelink Token and Expiration values
    .DESCRIPTION
        In order to retrieve data from carelink, you must authenticate with a browser so as to retrieve a valid Token ("auth_tmp_token") and
        Token Expiration Date ("c_token_valid_to").

        For example, using Dev Tools, copy the Token and Token Expiration date out. Using this cmdlet, you can set those values.
    .EXAMPLE
        Set-CareLinkToken -Expiration "Fri Nov 20 19:17:44 UTC 2023" -Token "c7822ebd1d9bf24609b7..."
  #>

  param (
    #The Expiration DateTime of the token. For example, Mon Nov 20 01:36:04 UTC 2023
    [parameter(Mandatory = $true, Position = 0)]
    [string]$Expiration,
    #The token to use when making calls to retrieve data, and request new tokens
    [parameter(Mandatory = $true, Position = 1)]
    [string]$Token
  )

  #set the carelink token variable to use within the module
  $script:CarelinkToken = [PSCustomObject]@{
    Expiration = "$Expiration"
    Token      = "$Token"
  }
}
