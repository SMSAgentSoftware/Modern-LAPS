#################
## MODERN LAPS ##
#################

# This script rotates the password for the local administrator account, encrypts it and sends it to the Azure Event Grid service.
# The script must run in administrative context

##############
# Parameters #
##############

# Name of local account to rotate password for. Example here gets the built in local administrator account from its SID
$script:LocalAccountName = (Get-LocalUser | Where-Object {$_.SID -like 'S-1-5-*-500'}).Name
# How frequently to rotate the password in days
$PasswordRotationFrequency = 7
# The name of the Source to use when creating entries in the Application event log
$script:EventLogSource = "LocalAdminPasswordRotation"
# The URL for the Azure Event Grid Topic endpoint
$script:EventGridTopicEndpoint = "https://mysolutionname.eastus2-1.eventgrid.azure.net/api/events"
# The Access key for the Azure Event Grid Topic
$script:EventGridTopicKey = "8utH6786HFGDR577H1swfMy7Zcu6emgRz4PWm8o="
# The AES encryption key used to encrypt the password for sending (as a base64 string)    
$script:ClientEncryptionKey = "9Inh8GFr%343dY&RhMkCkI5NQ+p2E/pjC2wEjA0="
# The intilization vector for the AES encryption key (as a base64 string)
$script:ClientEncryptionKeyIV = "j9uh&g7554%$^hhhY8kQk4KOfA=="
# Length of new password in characters
$script:PasswordLength = 14
# Regex expression for strong password
# Example: At least one upper case letter, at least 1 lower case letter, at least 1 number or special character, at least as long as $PasswordLength
# Ref: https://gist.github.com/ravibharathii/3975295
$script:PasswordRegex = "(?=^.{$PasswordLength,}$)((?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$"
# Registry location for script
$script:RegistryRoot = "HKLM:\SOFTWARE"
$script:RegistryVendorName = "SMSAgent"
$script:RegistryAppName = "Modern LAPS"
$script:RegistryPath = "$RegistryRoot\$RegistryVendorName\$RegistryAppName"


#############
# Functions #
#############

# Function to prevent an error running Invoke-WebRequest when IE has not yet been run
Function Disable-IEFirstRun {   
    $CurrentValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -ErrorAction SilentlyContinue | Select -ExpandProperty DisableFirstRunCustomize -ErrorAction SilentlyContinue
    If ($CurrentValue -ne 1)
    {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "Internet Explorer" -Force
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Name "Main" -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -PropertyType DWORD -Value 1 -Force
    }
}

# Function to create the registry location if required
Function Create-RegistryKeys {
    If (!(Test-Path -Path $RegistryRoot\$RegistryVendorName))
    {
        $null = New-Item -Path $RegistryRoot -Name $RegistryVendorName -Force
    }
    If (!(Test-Path -Path $RegistryRoot\$RegistryVendorName\$RegistryAppName))
    {
        $null = New-Item -Path $RegistryRoot\$RegistryVendorName -Name $RegistryAppName -Force
    }
}

# Function to create a strong password that meets domain complexity requirements
Function Script:Generate-StrongPassword 
{
    Param (
        [Parameter(Mandatory=$true)]
        [string]$PasswordRegex,
        [Parameter(Mandatory=$true)]
        [int]$PasswordLength
    )
    Add-Type -AssemblyName System.Web
    do {
        $newPassword=[System.Web.Security.Membership]::GeneratePassword($PasswordLength,1)
    } Until ([Regex]::IsMatch($newPassword,$PasswordRegex))
    return $newPassword
}

# Function to encrypt the password using AES
Function Script:Encrypt-Data {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)]
        [String]$Key,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=1)]
        [String]$IVector,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=2)]
        [String]$Data
    )

    $KeyBytes = [System.Convert]::FromBase64String($Key)
    $IVBytes = [System.Convert]::FromBase64String($IVector)
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $KeyBytes
    $aes.IV = $IVBytes

    $encryptor = $aes.CreateEncryptor()
    [System.Byte[]]$Bytes =  [System.Text.Encoding]::Unicode.GetBytes($Data)
    $EncryptedBytes = $encryptor.TransformFinalBlock($Bytes,0,$bytes.Length)
    $EncryptedBase64String = [System.Convert]::ToBase64String($EncryptedBytes)

    Return $EncryptedBase64String
}

# Function to rotate the password
Function Rotate-LocalAdministratorPassword {
    # Get the administrator account
    Try
    {
        $LocalAdministrator = Get-LocalUser -Name $LocalAccountName -ErrorAction Stop
    }
    Catch
    {
        Set-ItemProperty $RegistryPath -Name LastAttemptedRotationDateLocal -Value ([Datetime]::Now | Get-Date -Format "yyyy-MM-dd HH:mm:ss").ToString() -Force
        Set-ItemProperty $RegistryPath -Name PasswordRotationResult -Value "Failed" -Force
        Set-ItemProperty $RegistryPath -Name PasswordRotationErrorMessage -Value "Error getting local account '$LocalAccountName': $_" -Force
        Write-EventLog -LogName Application -Source $EventLogSource -EventId 65500 -EntryType Error -Message "Failed to rotate local administrator password. There was an error getting local account '$LocalAccountName': $_"
        Break
    }

    # Create, convert and set the password
    $Password = Generate-StrongPassword -PasswordRegex $PasswordRegex -PasswordLength $PasswordLength
    $SecurePassword = ConvertTo-SecureString "$Password" -AsPlainText -Force
    Try
    {
        Set-LocalUser -InputObject $LocalAdministrator -Password $SecurePassword -ErrorAction Stop
    }
    Catch
    {
        Set-ItemProperty $RegistryPath -Name LastAttemptedRotationDateLocal -Value ([Datetime]::Now | Get-Date -Format "yyyy-MM-dd HH:mm:ss").ToString() -Force
        Set-ItemProperty $RegistryPath -Name PasswordRotationResult -Value "Failed" -Force
        Set-ItemProperty $RegistryPath -Name PasswordRotationErrorMessage -Value "Error setting password for local account '$LocalAccountName': $_" -Force
        Write-EventLog -LogName Application -Source $EventLogSource -EventId 65501 -EntryType Error -Message "Failed to set the password for local account '$LocalAccountName': $_"
        Break
    }

    # Encrypt the password for sending
    $Script:EncryptedPassword = Encrypt-Data -Key $ClientEncryptionKey -IVector $ClientEncryptionKeyIV -Data $Password

    # Log the result
    $script:PasswordRotationDateUTC = [Datetime]::UtcNow | Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $script:PasswordRotationDateLocal = [Datetime]::Parse($PasswordRotationDateUTC).ToLocalTime() | Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $script:NextPasswordRotationDateUTC = [Datetime]::Parse($PasswordRotationDateUTC).AddDays($PasswordRotationFrequency) | Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Set-ItemProperty $RegistryPath -Name PasswordRotationDateLocal -Value $PasswordRotationDateLocal -Force
    Set-ItemProperty $RegistryPath -Name LastAttemptedRotationDateLocal -Value $PasswordRotationDateLocal -Force
    Set-ItemProperty $RegistryPath -Name PasswordRotationResult -Value "Success" -Force
    Set-ItemProperty $RegistryPath -Name PasswordRotationErrorMessage -Value "" -Force
    Set-ItemProperty $RegistryPath -Name PasswordRotationDateUTC -Value $PasswordRotationDateUTC -Force
    Set-ItemProperty $RegistryPath -Name NextPasswordRotationDateUTC -Value $NextPasswordRotationDateUTC -Force
    Write-EventLog -LogName Application -Source $EventLogSource -EventId 65502 -EntryType Information -Message "Password was successfully rotated for local account '$LocalAccountName': $_"

    # Call the upload function
    Upload-LocalAdminPassword

}

# Function to send password to Azure Event Grid service via http request
Function Script:Upload-LocalAdminPassword {
    Param(
        [Switch]$Retry
    )
    
    # If it's a retry we need to pull some values from the registry
    If ($Retry)
    {
        $SS = Get-ItemProperty -Path $RegistryPath -Name EncryptedString | Select -ExpandProperty EncryptedString | ConvertTo-SecureString -ErrorAction Stop
        $Credential = [PSCredential]::new("Data",$SS)
        $EncryptedPassword  = $Credential.GetNetworkCredential().Password
        $PasswordRotationDateUTC = Get-ItemProperty $RegistryPath -Name PasswordRotationDateUTC | Select -ExpandProperty PasswordRotationDateUTC
        $PasswordRotationDateLocal = Get-ItemProperty $RegistryPath -Name PasswordRotationDateLocal | Select -ExpandProperty PasswordRotationDateLocal
        $NextPasswordRotationDateUTC = Get-ItemProperty $RegistryPath -Name NextPasswordRotationDateUTC | Select -ExpandProperty NextPasswordRotationDateUTC
    }

    # Set the required values
    $ComputerName = $env:COMPUTERNAME
    $SerialNumber = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue | Select -ExpandProperty SerialNumber -ErrorAction SilentlyContinue   
    $LocalTimeZone = [Timezone]::CurrentTimeZone.StandardName
    $IsDaylightSaving = [Timezone]::CurrentTimeZone.IsDaylightSavingTime($PasswordRotationDateLocal)
    $UTCOffset = ([Timezone]::CurrentTimeZone.GetUtcOffset($PasswordRotationDateLocal)).TotalHours    
    $UploadDateUTC = [Datetime]::UtcNow | Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # Prepare hash table for the event body
    $eventID = Get-Random 99999      
    $eventDate = Get-Date -Format s # Date format should be SortableDateTimePattern (ISO 8601)
    $htbody = @{
        id= $eventID
        eventType="recordInserted"
        subject="Local Admin Password Rotation"
        eventTime= $eventDate   
        data= @{
            ComputerName = "$ComputerName"
            SerialNumber = "$SerialNumber"
            PasswordRotationDateUTC = "$PasswordRotationDateUTC"
            PasswordRotationDateLocal = "$PasswordRotationDateLocal"
            LocalTimezone = "$LocalTimeZone"
            IsDaylightSaving = "$IsDaylightSaving"
            UTCOffset = "$UTCOffset"
            NextPasswordRotationDateUTC = "$NextPasswordRotationDateUTC"
            Password = "$EncryptedPassword"
            UploadDateUTC = "$UploadDateUTC"
        }
        dataVersion="1.0"
    }

    # Send the request
    Try
    {
        $body = "["+(ConvertTo-Json $htbody)+"]"
        $Response = Invoke-WebRequest -Uri $eventgridtopicendpoint -Method POST -Body $body -Headers @{"aeg-sas-key" = $eventgridtopickey} -UseBasicParsing -ErrorAction Stop
    }
    # If failed, log the failure
    Catch
    {
        Set-ItemProperty $RegistryPath -Name PasswordUploadResult -Value "Failed" -Force
        Set-ItemProperty $RegistryPath -Name PasswordUploadErrorMessage -Value "$_" -Force
        Set-ItemProperty $RegistryPath -Name LastAttemptedUploadDateUTC -Value ([Datetime]::UtcNow | Get-Date -Format "yyyy-MM-dd HH:mm:ss").ToString() -Force
        If ($Retry)
        {}
        Else
        {            
            $SS = $EncryptedPassword | ConvertTo-SecureString -AsPlainText -Force
            Set-ItemProperty -Path $RegistryPath -Name EncryptedString -Value ($SS | ConvertFrom-SecureString) -Force             
        }
        Write-EventLog -LogName Application -Source $EventLogSource -EventId 65503 -EntryType Warning -Message "The password for local account '$LocalAccountName' could not be uploaded to the central repository. The password has been saved in encrypted form to the registry and upload will be attempted again later. The error was: $_"
        Break
    }

    # Log the result
    Set-ItemProperty $RegistryPath -Name UploadDateUTC -Value "$UploadDateUTC" -Force
    Set-ItemProperty $RegistryPath -Name LastAttemptedUploadDateUTC -Value "$UploadDateUTC" -Force
    Set-ItemProperty $RegistryPath -Name PasswordUploadErrorMessage -Value "" -Force
    Set-ItemProperty $RegistryPath -Name EncryptedString -Value "" -Force
    Set-ItemProperty $RegistryPath -Name PasswordUploadResult -Value "Success" -Force
    Write-EventLog -LogName Application -Source $EventLogSource -EventId 65504 -EntryType Information -Message "Password was successfully uploaded to central repository for local account '$LocalAccountName': $_"

    If ($Retry)
    {
        Break
    }
}


###############
# Main Script #
###############

# Remove Microsoft LAPS registry Keys if still present
#$Path = "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
#If (Test-Path -Path $Path)
#{
    #Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
#}

# Disable IEFirstRun if required
Disable-IEFirstRun

# Create the registry keys if required
Create-RegistryKeys

# Register event source
If (!([System.Diagnostics.EventLog]::SourceExists("$EventLogSource")))
{
    [System.Diagnostics.EventLog]::CreateEventSource("$EventLogSource","Application")
}

# Set TLS to 1.2 for secure transfer
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# Rotate local admin password for first run
$NextRotation = Get-ItemProperty $RegistryPath -Name NextPasswordRotationDateUTC -ErrorAction SilentlyContinue | Select -ExpandProperty NextPasswordRotationDateUTC -ErrorAction SilentlyContinue
If ($NextRotation.Length -eq 0)
{
    Rotate-LocalAdministratorPassword
}
Else
{
    # Rotate local admin password if due
    If ((($NextRotation | Get-Date) - ([Datetime]::UtcNow)).TotalMinutes -le 0)
    {
        Rotate-LocalAdministratorPassword
    }
    # Attempt to upload the password on a failed previous attempt
    ElseIf ((Get-ItemProperty $RegistryPath -Name PasswordUploadResult | Select -ExpandProperty PasswordUploadResult) -eq "Failed")
    {
        Upload-LocalAdminPassword -Retry
    }
}