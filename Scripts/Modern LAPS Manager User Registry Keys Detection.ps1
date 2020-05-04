#########################
## MODERN LAPS MANAGER ##
#########################

# This script checks that the HKCU registry keys required by the Modern LAPS Manager app are present with the correct values
# It is intended to be used a a detection script for a Configuration item in Configuration Manager
# This script must run in the user context


# Reg Key Values
$DataHash = @{
    KeyVaultURL = "https://mykeyvault.vault.azure.net/"
    KeyVaultAPIVersion = "api-version=7.0"
    ActiveEncryptionKeyName = "Active-Encryption-Key"
    ActiveEncryptionKeyIVName = "Active-Encryption-Key-IV"
    PreviousEncryptionKeyName = "Previous-Encryption-Key"
    PreviousEncryptionKeyIVName = "Previous-Encryption-Key-IV"
    BaselineCIUniqueIDName = "Baseline-CIUniqueID"
    ClientAppID = "7577e370-cf2a-1234-9856-41222f15e24f"
    ClientAppRedirectURI = "https://login.live.com/oauth20_desktop.srf"
    FunctionURL = "myfunctionapp.azurewebsites.net/api/Get-PasswordFromDatabase?code=8m49fme9dm303otikMli92qKNSxc6j1nDrV8fmd71JO2Yx3YS4w=="
}

# Reg key names
$RegBase = "HKCU"
$RegBranch = "Software"
$AppVendor = "SMSAgent"
$AppName = "Modern LAPS Manager"

# Check for reg keys
If (!(Test-Path "$RegBase`:\$RegBranch\$AppVendor"))
{
    Write-Host "Reg keys not present"
    Break
}
If (!(Test-Path "$RegBase`:\$RegBranch\$AppVendor\$AppVendor"))
{
    Write-Host "Reg keys not present"
    Break
}

# Decrypt and check each registry key encrypted string
Foreach ($Key in $DataHash.Keys)
{
    $DecryptedString = Get-ItemProperty -Path "$RegBase`:\$RegBranch\$AppVendor\$AppName" -Name $Key -ErrorAction SilentlyContinue | Select -ExpandProperty $Key | ConvertTo-SecureString
    If (([PSCredential]::new("Data",$DecryptedString).GetNetworkCredential().Password) -ne $DataHash[$key])
    {
        Write-Host "$Key doesn't match"
        Break
    } 
}

Write-host "Compliant"