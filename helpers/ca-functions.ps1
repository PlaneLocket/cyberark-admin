#global declarations
$pvwa_base_url = "https://pvwa.pas.local/PasswordVault/"
$ccp_base_url = "https://ccp.pas.local/"
$ccp_app_id = "<cyberark_app_id>"
$ccp_safe = "<admin_access_safe>"
$ccp_account_to_retrieve = "<internal_admin_account>"

<#
    Function used for retrieving a credential via the central credential provider
    documentation: https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-CP/Latest/en/Content/CCP/Calling-the-Web-Service-using-REST.htm?tocpath=Developer%7CCentral%20Credential%20Provider%7CCall%20the%20Central%20Credential%20Provider%20Web%20Service%20from%20Your%20Application%20Code%7C_____2
    params: 
        username: account to be retrieved
        safe: safe to be searched
        app_id: cyberark internal app id that has access to $safe
    returns: requested secret
#>
function Get-Credential(){
    Param(
        [Parameter (Mandatory = $true)] [String]$username,
        [Parameter (Mandatory = $true)] [String]$safe,
        [Parameter (Mandatory = $true)] [String]$app_id
    )
    #search query
    $url = $ccp_base_url + "AIMWebService/api/Accounts?AppID=$app_id&Safe=$safe&Query=Username=$username"
    try{
        $response = Invoke-RestMethod -Uri $url -Method 'GET' -ContentType 'application/json'
        #only return the secret from the json response
        return $response.Content
    }
    catch{
        Write-Output "An error occurred retrieving logon credentials."
        Write-Output $_
    }
}


<#
    Function used to log onto cyberark using an internal account and retrieve an auth token to be used in subsequent REST calls
    documentation: https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/12.1/en/Content/SDK/CyberArk%20Authentication%20-%20Logon_v10.htm?tocpath=Developer%7CREST%20APIs%7CAuthentication%7CLogon%7C_____1
    params:
        logon_username: account to login with
        secret: password 
    returns: authorization token
#>
function Invoke-PVWALogonV2(){
    Param(
        [Parameter (Mandatory = $true)] [String]$logon_username,
        [Parameter (Mandatory = $true)] [String]$secret
    )
    $url = $pvwa_base_url + "API/auth/Cyberark/Logon/"
    
    $body_obj = New-Object -TypeName psobject
    $body_obj | Add-Member -MemberType NoteProperty -Name 'username' -Value $logon_username
    $body_obj | Add-Member -MemberType NoteProperty -Name 'password' -Value $secret
    $body_obj | Add-Member -MemberType NoteProperty -Name 'useRadiusAuthentication' -Value 'false'

    $body_json = $body_obj | ConvertTo-Json -Depth 5
    

    try{
        $response = Invoke-RestMethod -Uri $url -Method 'POST' -Body $body_json -ContentType 'application/json'
        #authorization token
        return $response
    }
    catch{
        Write-Output "An error occurred during logon." 
        Write-Output $_
    }
}
<#
    Function used to logoff a cyberark session using an internal account/auth token that was used in subsequent REST calls
    documentation: https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/12.1/en/Content/SDK/CyberArk%20Authentication%20-%20Logon_v10.htm?tocpath=Developer%7CREST%20APIs%7CAuthentication%7CLogon%7C_____1
    params:
        token: current session auth token to be logged off
    returns: null
#>
function Invoke-PVWALogoffV2(){
    Param(
        [Parameter (Mandatory = $true)] [String]$token
    )
    try {
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", $token)
    $headers.Add("Content-Type", "application/json")

    $url = $pvwa_base_url + "API/Auth/Logoff/"
    Invoke-RestMethod -Uri $url -Method "POST" -Header $headers
    }
    catch{
        Write-Output "An error occurred during logon that could not be resolved." 
        Write-Output $_       
    }
}
<#
    Link a logon or reconcile account to an existing, onboarded account
    NOTE: this function requires an already existing logon token since it's current scope is only being used during account onboard.  
          A call to logon/logoff can be added to the function if it's later determined to be needed as a standalone encapsulated function
    documentation: https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/12.1/en/Content/WebServices/Link-account.htm?tocpath=Developer%7CREST%20APIs%7CAccounts%7CLinked%20accounts%7C_____1
    Params:
        link_acct_name: recon/logon account name
        link_acct_safe: safe where recon/logon account is stored
        link_acct_folder: safe folder where recon/logon is stored: always "root" unless object level access control is enabled on the safe
        index:      #1 Logon Account
                    #2 Enable Account
                    #3 Reconcile Account
        acct_id: account being linked to
        token: authorization token of current session
    returns: return code
#>
function Invoke-LinkAccount(){
    Param(
        [Parameter (Mandatory = $false)] [String]$link_acct_name,
        [Parameter (Mandatory = $false)] [String]$link_acct_safe,
        [Parameter (Mandatory = $false)] [String]$link_acct_folder,
        [Parameter (Mandatory = $false)] [String]$index,
        [Parameter (Mandatory = $false)] [String]$acct_id,
        [Parameter (Mandatory = $false)] [String]$token
    )

    $link_acct = New-Object System.Object
    $link_acct | Add-Member -MemberType NoteProperty -Name "safe" -Value $link_acct_safe
    $link_acct | Add-Member -MemberType NoteProperty -Name "extraPasswordIndex" -Value $index
    $link_acct | Add-Member -MemberType NoteProperty -Name "name" -Value $link_acct_name
    $link_acct | Add-Member -MemberType NoteProperty -Name "folder" -Value $link_acct_folder
    
    $body = $link_acct | ConvertTo-Json -Depth 5
  
    $url = $pvwa_base_url + "api/Accounts/$acct_id/LinkAccount"
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", $token)
    $headers.Add("Content-Type", "application/json")
    try {
        $response = Invoke-RestMethod -Uri $url -Method "POST" -Body $body -ContentType "application/json" -Headers $headers
        return $response
    }
    Catch{
        Write-Output "Linked Account Not Added"
        Write-Output $_  
    }
}
<#
    Add a new account into CyberArk using the new V2 endpoint
    documentation: https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/12.1/en/Content/WebServices/Add%20Account%20v10.htm?tocpath=Developer%7CREST%20APIs%7CAccounts%7C_____5
    Params:
        username: account username
        address: account address (either domain or machine fqdn/ip)
        secret: the password or key to be managed
        safename: the safe to store the credential in
        platformid: the managing platform for the account
        secret_type: either "password" or "key"
        logon_acct: object name of the logon account, if required
        logon_safe: safe the logon account is stored in
        recon_acct: object name of the reconcile account, if required
        recon_safe: safe the reconcile account is stored in
    returns: account id that was onboarded
#>
function Add-AccountV2(){
    Param(
        [Parameter (Mandatory = $true)] [String]$username,        
        [Parameter (Mandatory = $true)] [String]$address,
        [Parameter (Mandatory = $true)] [String]$secret,
        [Parameter (Mandatory = $true)] [String]$safename,
        [Parameter (Mandatory = $true)] [String]$platformID,
        [Parameter (Mandatory = $true)] [String]$secret_type,
        [Parameter (Mandatory = $false)] [String]$logon_acct,
        [Parameter (Mandatory = $false)] [String]$logon_safe,
        [Parameter (Mandatory = $false)] [String]$recon_acct,
        [Parameter (Mandatory = $false)] [String]$recon_safe
    )

    #build the base json of the account object
    $account = New-Object System.Object
    $account | Add-Member -MemberType NoteProperty -Name "safeName" -Value "$safename"
    $account | Add-Member -MemberType NoteProperty -Name "platformId" -Value "$platformID"
    $account | Add-Member -MemberType NoteProperty -Name "address" -Value "$address"
    $account | Add-Member -MemberType NoteProperty -Name "secret" -Value "$secret"
    $account | Add-Member -MemberType NoteProperty -Name "secretType" -Value "$secret_type"
    $account | Add-Member -MemberType NoteProperty -Name "userName" -Value "$username"
    
    $body = $account | ConvertTo-Json -Depth 5

    #logon to the pvwa and retrieve and authorization token
    $credential = Get-Credential -username $ccp_account_to_retrieve -safe $ccp_safe -app_id $ccp_app_id
    $token = Invoke-PVWALogonV2 -logon_username $ccp_account_to_retrieve -secret $credential
    
    #add token to the REST call header
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", $token)
    $headers.Add("Content-Type", "application/json")

    $url = $pvwa_base_url +"API/Accounts/"

    #onboard the account
    try {
        $response = Invoke-RestMethod -Uri $url -Method "POST" -Body $body -ContentType "application/json" -Headers $headers
    
        #response has the new account id.  this is needed for linking logon/reconcile, if required
        $acct_id = $response.id

        #iff logon account was passed in, add it
        if(![string]::IsNullOrEmpty($logon_acct)){
            try{
                Invoke-LinkAccount -link_acct_name $logon_acct -link_acct_safe $logon_safe -index 1 -link_acct_folder "root" -acct_id $acct_id -token $token
            }
            Catch{
                Write-Output "Logon Account Not Added"
                Write-Output $_  
            }
        }
        #iff logon account was passed in, add it
        if(![string]::IsNullOrEmpty($recon_acct)){
            try{
                Invoke-LinkAccount -link_acct_name $recon_acct -link_acct_safe $recon_safe -index 3 -link_acct_folder "root" -acct_id $acct_id -token $token
            }
            Catch{
                Write-Output "Recon Account Not Added"
                Write-Output $_  
            }
        }
        #logoff the session
        Invoke-PVWALogoffV2 -token $token
        return $response
    }

    Catch{
        Write-Output "Account Not Added"
        Write-Output $_  
    }

}
<#
    find an account by searching by username/address with a particular safe
    documentation: https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/12.1/en/Content/SDK/GetAccounts.htm?tocpath=Developer%7CREST%20APIs%7CAccounts%7C_____1 
    Params:
        username: username to be searched
        address: address to be searched
        safe: safe to search in
        token: authorization token
    returns: account(s) that match search
#>

function Get-AccountIDByUsernameAddress(){
    Param(
        [Parameter (Mandatory = $true)] [String]$username,
        [Parameter (Mandatory = $true)] [String]$address,
        [Parameter (Mandatory = $true)] [String]$safe,
        [Parameter (Mandatory = $true)] [String]$token
    )

     $url = $pvwa_base_url + "/api/Accounts?filter=safeName eq $safe&search=$username $address"

     #add token to the REST call header
     $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
     $headers.Add("Authorization", $token)
     $headers.Add("Content-Type", "application/json") 
     try {
         $response = Invoke-RestMethod -Uri $url -Method "GET" -ContentType "application/json" -Headers $headers
         return $response
     }
     catch{
         Write-Output "Account(s) Not Retrieved"
         Write-Output $_  
     }
}
<#
    find a safe(s) by searching by safe name
    documentation: https://docs.cyberark.com/PAS/12.6/en/Content/SDK/Safes%20Web%20Services%20-%20List%20Safes.htm?tocpath=Developer%7CREST%20APIs%7CSafes%7C_____5
    Params:
        query: search string
        token: authorization token
    returns: safe(s) that match search
#>
function Get-SafesBySearchString(){
    Param(
        [Parameter (Mandatory = $true)] [String]$query,
        [Parameter (Mandatory = $true)] [String]$token
    )

     $url = $pvwa_base_url + "/api/safes?search=$query"

     #add token to the REST call header
     $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
     $headers.Add("Authorization", $token)
     $headers.Add("Content-Type", "application/json") 
     try {
         $response = Invoke-RestMethod -Uri $url -Method "GET" -ContentType "application/json" -Headers $headers
         return $response
     }
     catch{
         Write-Output "Safes(s) Not Retrieved"
         Write-Output $_  
     }
}
<#
    get members and permissions for a safe
    documentation: https://docs.cyberark.com/PAS/12.6/en/Content/SDK/Safe%20Members%20WS%20-%20List%20Safe%20Members.htm?tocpath=Developer%7CREST%20APIs%7CSafes%7CSafe%20members%7C_____5
    Params:
        safe_id: safe to query
        token: authorization token
    returns: safe(s) that match search
#>
function Get-SafeMembers(){
    Param(
        [Parameter (Mandatory = $true)] [String]$safe_id,
        [Parameter (Mandatory = $true)] [String]$token
    )

     $url = $pvwa_base_url + "/api/Safes/$safe_id/Members/"

     #add token to the REST call header
     $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
     $headers.Add("Authorization", $token)
     $headers.Add("Content-Type", "application/json") 
     try {
         $response = Invoke-RestMethod -Uri $url -Method "GET" -ContentType "application/json" -Headers $headers 
         return $response.value
     }
     catch{
         Write-Output "Account(s) Not Retrieved"
         Write-Output $_  
     }
}
function Update-Password(){
    Param(
        [Parameter (Mandatory = $true)] [String]$token,
        [Parameter (Mandatory = $true)] [String]$account_id,
        [Parameter (Mandatory = $true)] [SecureString]$new_password
    )
    #search query
    $url = $pvwa_base_url + "/PasswordVault/API/Accounts/$account_id/Password/Update/"

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", $token)
    $headers.Add("Content-Type", "application/json") 

    try{
        $body = @{NewCredentials = $new_password} | ConvertTo-Json -Depth 1
        $response = Invoke-RestMethod -Uri $url -Method 'POST' -ContentType 'application/json' -Body $body

            
        #only return the secret from the json response
        return $response.Content
    }
    catch{
        Write-Output "An error occurred retrieving logon credentials."
        Write-Output $_
    }
}
<#
    retrieve account details from CyberArk
    documentation: https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/12.1/en/Content/WebServices/Get%20Account%20Details.htm?tocpath=Developer%7CREST%20APIs%7CAccounts%7C_____2
    Params:
        account_id: ID of the account to be retrieved        
    Returns: account details - json
#>
function Get-AccountDetails(){
    Params(
        [Parameter (Mandatory = $true)] [String]$account_id
    )

    #add token to the REST call header
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", $token)
    $headers.Add("Content-Type", "application/json")

    $url = $pvwa_base_url + "/api/Accounts/$account_id"

    #logon to the pvwa and retrieve and authorization token
    $credential = Get-Credential -username $ccp_account_to_retrieve -safe $ccp_safe -app_id $ccp_app_id
    $token = Invoke-PVWALogonV2 -logon_username $ccp_account_to_retrieve -secret $credential

    try {
        $response = Invoke-RestMethod -Uri $url -Method "GET" -ContentType "application/json" -Headers $headers 
        return $response
    }
    catch{
        Write-Output "Account Not Retrieved"
        Write-Output $_  
    }
    
}
<#
    Helper function to open a file dialog box restricted to csv files
#>
Function Get-FileName($initialDirectory)
{
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
    
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.initialDirectory = $initialDirectory
    $OpenFileDialog.filter = "CSV (*.csv)| *.csv"
    $OpenFileDialog.ShowDialog() | Out-Null
    $OpenFileDialog.FileName
}

<#
    Function used to reconcile an account within cyberark 
    documentation: https://docs.cyberark.com/PAS/12.6/en/Content/WebServices/Reconcile-account.htm?tocpath=Developer%7CREST%20APIs%7CAccounts%7CAccount%20actions%7C_____13
    params:
        account_id: internal cyberark id of account to be reconciled
        token: current session auth token to be logged off
    returns: null
#>
Function Invoke-AccountCredentialReconcile{
    PARAM(
        $account_id,
        $token
    )
    
    begin{}

    process{
        
        try{
        #add token to the REST call header
            $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
            $headers.Add("Authorization", $token)
            $headers.Add("Content-Type", "application/json") 

            $url = "https://cyberarkpvwa.deere.com/PasswordVault/api/Accounts/$account_id/Reconcile"
            $body = @{ImmediateChangeByCPM="Yes";ChangeCredsForGroup="No"} |ConvertTo-Json -Depth 1
            $Result = Invoke-RestMethod -Uri $url -Method POST -body $Body -ContentType "application/json" -Headers $headers
        }
        catch{
            $Error
        }
    }

    end{

        return $Result

    }
}

<#
    Function used to delete an account within cyberark 
    documentation: https://docs.cyberark.com/PAS/12.6/en/Content/WebServices/Delete%20Account.htm?tocpath=Developer%7CREST%20APIs%7CAccounts%7C_____8
    params:
        account_id: internal cyberark id of account to be reconciled
        token: current session auth token to be logged off
    returns: null
#>
function Invoke-DecommissionAccount{
        PARAM(
            $account_id,
            $token
        )
        begin{}

        process{
            
            try{
            #add token to the REST call header
                $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
                $headers.Add("Authorization", $token)
                $headers.Add("Content-Type", "application/json") 
    
                $url = "https://cyberarkpvwa.deere.com/PasswordVault/api/Accounts/$account_id/"
                $Result = Invoke-RestMethod -Uri $url -Method DELETE -ContentType "application/json" -Headers $headers
            }
            catch{
                $Error
            }
        }
    
        end{
    
            return $Result
    
        }
}

<#
    Function used to retrieve disabled accounts from a particular safe within CyberArk using a combination of predefined filters and savedFilters
    documentation: https://docs.cyberark.com/PAS/12.6/en/Content/SDK/GetAccounts.htm?tocpath=Developer%7CREST%20APIs%7CAccounts%7C_____1 
    params:
        safe: safe to be searched
        token: current session auth token to be logged off
    returns: null
#>
function Get-DisabledAccounts(){
    Param(
        [Parameter (Mandatory = $true)] [String]$safe,
        [Parameter (Mandatory = $true)] [String]$token
    )
    $url = $pvwa_base_url + "/api/Accounts?filter=safeName eq $safe &savedFilter=DisabledPasswordByCPM"
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", $token)
    $headers.Add("Content-Type", "application/json") 
    try {
        $response = Invoke-RestMethod -Uri $url -Method "GET" -ContentType "application/json" -Headers $headers
        return $response
    }
    catch{
        Write-Output "Account(s) Not Retrieved"
        Write-Output $_  
    }
}
<#
    Function to get safe membership report by partial safe name query 
    params:
        $query: safe name 
    returns: null
    saves: report in this directory
#>
function Get-MembershipReportBySearchQuery(){
    [Parameter (Mandatory = $true)] [String]$query
}

function Get-Connection(){

    Param(
        [Parameter (Mandatory = $true)] [String]$token,
        [Parameter (Mandatory = $true)] [String]$safe
    )
    $account = Get-AccountIDByUsernameAddress -username "<account_username>" -address "<account_address>" -safe $safe -token $token
    $accountID = $account.value[0].id

    $url = $pvwa_base_url + "/api/Accounts/$accountID/psmconnect"
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", $token)
    $headers.Add("Content-Type", "application/json") 

    $body = @"
    {
        "reason":"",
        "TicketingSystemName":"",
        "TicketId":"",
        "ConnectionComponent":"PSM-TOTPToken"
    }
"@

  try {
      $response = Invoke-RestMethod -Uri $url -Method "POST" -ContentType "application/json" -Headers $headers -Body $body
      return $response
  }
  catch{
      Write-Output "Connection(s) Not Retrieved"
      Write-Output $_  
  }
}

