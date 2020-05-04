#########################
## MODERN LAPS MANAGER ##
#########################

# This script creates and populates the registry keys and values required for the Modern LAPS Manager app
# Each value is stored as a secure string which can only be decrypted on the same computer and by the same user context that created it
# This script must run in the user context
# The names of the registry keys cannot be changed - they are hard-coded into the app
# Intended for use as a Configuration item remediation script

# Reg Key Values
$DataHash = @{
    KeyVaultURL = "https://mykeyvault.vault.azure.net/"
    KeyVaultAPIVersion = "api-version=7.0"
    ActiveEncryptionKeyName = "Active-Encryption-Key"
    ActiveEncryptionKeyIVName = "Active-Encryption-Key-IV"
    PreviousEncryptionKeyName = "Previous-Encryption-Key"
    PreviousEncryptionKeyIVName = "Previous-Encryption-Key-IV"
    BaselineCIUniqueIDName = "Baseline-CIUniqueID"
    ClientAppID = "7577e370-cf2a-1234-9563-41222f15e24f"
    ClientAppRedirectURI = "https://login.live.com/oauth20_desktop.srf"
    FunctionURL = "myfunctionapp.azurewebsites.net/api/Get-PasswordFromDatabase?code=94j94jr03kdkt03kMli92qKNSxc6j1nDrV8fmd71JO2Yx3YS4w=="
}

# Reg key names
$RegBase = "HKCU"
$RegBranch = "Software"
$AppVendor = "SMSAgent"
$AppName = "Modern LAPS Manager"

# Create and set reg keys
If (!(Test-Path "$RegBase`:\$RegBranch\$AppVendor"))
{
    $null = New-Item -Path "$RegBase`:\$RegBranch" -Name $AppVendor -Force
}
If (!(Test-Path "$RegBase`:\$RegBranch\$AppVendor\$AppVendor"))
{
    $null = New-Item -Path "$RegBase`:\$RegBranch\$AppVendor" -Name $AppName -Force
}
Foreach ($Key in $DataHash.Keys)
{
    If ((Get-ItemProperty -Path "$RegBase`:\$RegBranch\$AppVendor\$AppName" -Name $Key -ErrorAction SilentlyContinue) -eq $null)
    {
        $null = New-ItemProperty -Path "$RegBase`:\$RegBranch\$AppVendor\$AppName" -Name $Key -PropertyType String -Value $null -Force
    } 
}

# Populate reg key values with secure strings
foreach ($Key in $DataHash.Keys)
{
    $SS = $DataHash[$key] | ConvertTo-SecureString -AsPlainText -Force
    Set-ItemProperty -Path "$RegBase`:\$RegBranch\$AppVendor\$AppName" -Name $Key -Value ($SS | ConvertFrom-SecureString) -Force
}
