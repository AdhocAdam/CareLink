<h1 align="center">
  <br>
  <img width="400" src="https://user-images.githubusercontent.com/6636040/216787966-a0d875c5-dcbe-4eba-849b-79229768c4b2.png">
  <br>
    CareLink for PowerShell
  <br>
</h1>

## Overview

This PowerShell module is for diabetics looking to retrieve their blood glucose readings from Medtronic Carelink. This is achieved using PowerShell's native [Invoke-WebRequest](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest?view=powershell-7.3) and [Invoke-RestMethod](https://learn.microsoft.com/en-us/powershell/module/Microsoft.PowerShell.Utility/Invoke-RestMethod?view=powershell-5.1)'s cmdlets.

This module is compatible with PowerShell 5.1 and up. It has been tested and confirmed working with a 770g. Pull Requests are welcome!

## Available cmdlets

| Cmdlet                |    Purpose    |
| --------------------- | ------------- |
| Get-CareLinkToken     | Retrieves the token currently in use  |
| Set-CareLinkToken     | Sets the token and expiration date to use in subsequent cmdlets  |
| Confirm-CareLinkToken | Used by other functions to confirm your authentication to Carelink is still valid |
| Get-CareLinkAccount   | Retrieves information about your account such as login date, account id, and user role |
| Get-CareLinkProfile   | Retrieves information about your profile such as username, phone number, email, etc. |
| Get-CareLinkData      | Retrieves a detailed object that contains device information, serial number, reservoir levels, last sugar, last 24 hours of sugars, etc. |

## Getting Started

Since the CareLink data model or command line may not be the most intuitive thing to most users. It's suggested to use either PowerShell ISE (built into Windows) or [VSCode](https://code.visualstudio.com/) to build scripts, debug, and visualize information. For the purposes of demonstration below, examples will take place in VSCode.

Install from the module from the PowerShell Gallery by using the following at a PowerShell prompt

```powershell
Install-Module -Name CareLink
```

## Authenticate to CareLink

In order to retrieve data, you must first obtain an access token and its expiration date. One means of doing this is:
1. Open a browser
2. Log into CareLink
3. Push F12 to open up Developer Tools and navigate to the Network Tab
4. Then in CareLink navigate to Data Connect to view your live glucose data
5. In the list of calls made in the Network tab, filter down for one called "message"

Inspect the Headers to copy out the Token and the Token's Expiration Date. You're looking for values that correspond with "c_token_valid_to" and "auth_tmp_token". Then paste them into the following cmdlet.

```powershell
Set-CareLinkToken -Expiration "Fri Nov 20 19:17:44 UTC 2023" -Token "c7822ebd1d9bf24609b7..."
```

Tokens are good for approximatley 40 minutes

## Get account/profile details

Once you have a token, use it with subsequent cmdlets to retrieve more information such as your Account and Profile information. You'll ultimately need these to access your sugar data.

```powershell
$account = Get-CarelinkAccount
$userProfile = Get-CarelinkProfile
```

## Retrieve last sugar, last 24 hours of sugar, device serial number, etc.

Using the $token, $account, and $userProfile variables. Pass them as values to the Get-CareLinkData cmdlet to retrieve pertinent information. Save the entire object to a variable such as $data to explore.

```powershell
$data = Get-CarelinkData -CarelinkUserAccount $account -CarelinkUserProfile $userProfile
```

## PowerShell ISE/VSCode exploration

This is where it makes sense to have performed the above commands in one of these two programs as you can just open a new tab to explore the object without continuing to make repeated calls to CareLink. Take the following gif wherein all the commands are executed in a window, then a new window is opened just to explore the $data variable.

![loadData01](https://user-images.githubusercontent.com/6636040/216782943-6a18ab1e-349f-4bd7-a50e-61c261c1bdf2.gif)

In VSCode you either use CTRL+N to open a new tab/file, or just head over to File -> New File. Set the language to PowerShell, then hit F5 to run it.

![image](https://user-images.githubusercontent.com/6636040/216783020-cc6de797-0430-48c8-978d-f1891b4a2ed7.png)

If you want to interrogate a specific data point, just add a "." to the end of data to grab specific data points. For example:
- $data.sgs
- $data.timeFormat

or if you prefer, you can also use the PowerShell pipeline:
```powershell
$data | Select-Object sgs, timeFormat, markers
```

## Filter the sugars

If you were to use $data.sgs, you'd return a list of sugar objects from oldest to most recent. Using PowerShell, we can filter this down such as the last 10 readings, most recent reading, readings with a range, etc.

## The last reading(s)
```powershell
$data.sgs | Select-Object -Last 1
$data.sgs | Select-Object -Last 10
```

## All readings above (greater than) 160
```powershell
$data.sgs | Where-Object {$_.sg -gt 160}
```

## Readings between a given range
```powershell
$data.sgs | Where-Object {($_.sg -ge 90) -and ($_.sg -le 160)}
```

# Disclaimer
This project and subsequent PowerShell Module is not associated, affiliated, endorsed, or supported in any capacity by Medtronic or Microsoft. Use of this module is undertaken entirely at your own risk.
