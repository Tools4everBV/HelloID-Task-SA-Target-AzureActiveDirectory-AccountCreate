# HelloID-Task-SA-Target-AzureActiveDirectory-AccountCreate
###########################################################
# Form mapping
$formObject = @{
    userType          = $form.UserType
    displayName       = $form.DisplayName
    userPrincipalName = $form.UserPrincipalName
    givenName         = $form.GivenName
    surName           = $form.SurName
    mail              = $form.Mail
    department        = $form.Department
    mailNickName      = $form.MailNickName
    showInAddressList = [bool]$form.ShowInAddressList
    accountEnabled    = [bool]$form.AccountEnabled
    passwordProfile   = @{
        password = $form.Password
        forceChangePasswordNextSignIn = [bool]$formObject.ForceChangePasswordNextSignIn
    }
}

try {
    Write-Information "Executing AzureActiveDirectory action: [CreateAccount] for: [$($formObject.DisplayName)]"
    Write-Information "Retrieving Microsoft Graph AccessToken for tenant: [$AADTenantID]"
    $splatTokenParams = @{
        Uri         = "https://login.microsoftonline.com/$AADTenantID/oauth2/token"
        ContentType = 'application/x-www-form-urlencoded'
        Method      = 'POST'
        Body = @{
            grant_type    = 'client_credentials'
            client_id     = $AADAppID
            client_secret = $AADAppSecret
            resource      = 'https://graph.microsoft.com'
        }
    }
    $accessToken = (Invoke-RestMethod @splatTokenParams).access_token
    Write-Information "Creating AzureActiveDirectoryAccount for: [$($formObject.DisplayName)]"
    $splatCreateUserParams = @{
        Uri     = 'https://graph.microsoft.com/v1.0/users'
        Method  = 'POST'
        Body    = $formObject | ConvertTo-Json -Depth 10
        Verbose = $false
        Headers = @{
            Authorization  = "Bearer $accessToken"
            Accept         = 'application/json'
            'Content-Type' = 'application/json'
        }
    }
    $response = Invoke-RestMethod @splatCreateUserParams
    $auditLog = @{
        Action            = 'CreateAccount'
        System            = 'AzureActiveDirectory'
        TargetIdentifier  = $response.id
        TargetDisplayName = $formObject.displayName
        Message           = "AzureActiveDirectory action: [CreateAccount] for: [$($formObject.DisplayName)] executed successfully"
        IsError           = $false
    }
    Write-Information -Tags 'Audit' -MessageData $auditLog
    Write-Information "AzureActiveDirectory action: [CreateAccount] for: [$($formObject.DisplayName)] executed successfully"
} catch {
    $ex = $_
    $auditLog = @{
        Action            = 'CreateAccount'
        System            = 'AzureActiveDirectory'
        TargetIdentifier  = ''
        TargetDisplayName = $formObject.displayName
        Message           = "Could not execute AzureActiveDirectory action: [CreateAccount] for: [$($formObject.DisplayName)], error: $($ex.Exception.Message)"
        IsError           = $true
    }
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException')){
        $auditLog.Message = "Could not execute AzureActiveDirectory action: [CreateAccount] for: [$($formObject.DisplayName)]"
        Write-Error "Could not execute AzureActiveDirectory action: [CreateAccount] for: [$($formObject.DisplayName)], error: $($ex.ErrorDetails)"
    }
    Write-Information -Tags "Audit" -MessageData $auditLog
    Write-Error "Could not execute AzureActiveDirectory action: [CreateAccount] for: [$($formObject.DisplayName)], error: $($ex.Exception.Message)"
}
###########################################################
