using namespace System.Net
using namespace System.Data
using namespace System.Data.SqlClient
using namespace System.Security.Cryptography

param($eventGridEvent, $TriggerMetadata)

# Output basic info about this execution
Write-Host "Receiving new password for $($eventGridEvent.data.ComputerName) (Serial Number: $($eventGridEvent.data.SerialNumber))"

# Retrieve some variables
$MSI_ENDPOINT = [System.Environment]::GetEnvironmentVariable("MSI_ENDPOINT")
$MSI_SECRET = [System.Environment]::GetEnvironmentVariable("MSI_SECRET")
$ConnectionString = [System.Environment]::GetEnvironmentVariable("SQL Connection String")
$ClientEncryptionKey = [System.Environment]::GetEnvironmentVariable("Client Encryption Key")
$ClientEncryptionKeyIV = [System.Environment]::GetEnvironmentVariable("Client Encryption Key IV")
$ServerEncryptionKey = [System.Environment]::GetEnvironmentVariable("Server Encryption Key")
$ServerEncryptionKeyIV = [System.Environment]::GetEnvironmentVariable("Server Encryption Key IV")

# Function to Encrypt Data
Function Encrypt-Data {
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

# Function to Decrypt Data
Function Decrypt-Data {
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

    $EncryptedBytes = [System.Convert]::FromBase64String($Data)
    $Decryptor = $aes.CreateDecryptor()
    $DecryptedBytes = $Decryptor.TransformFinalBlock($EncryptedBytes,0,$EncryptedBytes.Length)
    $DecryptedString = [System.Text.Encoding]::Unicode.GetString($DecryptedBytes)

    Return $DecryptedString
}

# Decrypt password with Client Key
$DecryptedPassword = Decrypt-Data -Key $ClientEncryptionKey -IVector $ClientEncryptionKeyIV -Data $eventGridEvent.data.Password

# Encrypt password with Server Key
$EncryptedPassword = Encrypt-Data -Key $ServerEncryptionKey -IVector $ServerEncryptionKeyIV -Data $DecryptedPassword

# Obtain access token for function app managed identity for database audience
$tokenAuthURI = "$MSI_ENDPOINT`?resource=https://database.windows.net/&api-version=2017-09-01"
$tokenResponse = Invoke-RestMethod -Method Get -Headers @{"Secret"="$MSI_SECRET"} -Uri $tokenAuthURI
$accessToken = $tokenResponse.access_token

# SQL Query
$Query = "
INSERT INTO [dbo].[LocalAdminPasswords] (
	ComputerName,
    SerialNumber,
    PasswordRotationDateUTC,
    PasswordRotationDateLocal,
    LocalTimezone,
    IsDaylightSaving,
    UTCOffset,
    NextPasswordRotationDateUTC,
    Password,
    UploadDateUTC
)
VALUES (
	'$($eventGridEvent.data.ComputerName)',
	'$($eventGridEvent.data.SerialNumber)',
	'$($eventGridEvent.data.PasswordRotationDateUTC)',
	'$($eventGridEvent.data.PasswordRotationDateLocal)',
	'$($eventGridEvent.data.LocalTimezone)',
	'$($eventGridEvent.data.IsDaylightSaving)',
	'$($eventGridEvent.data.UTCOffset)',
    '$($eventGridEvent.data.NextPasswordRotationDateUTC)',
    '$EncryptedPassword',
    '$($eventGridEvent.data.UploadDateUTC)'
)
"

# Run the query
Try
{
    $connection = New-Object -TypeName System.Data.SqlClient.SqlConnection
    $connection.ConnectionString = $connectionString
    $connection.AccessToken = $accessToken
    $connection.Open()
    $command = $connection.CreateCommand()
    $command.CommandText = $Query
    $command.ExecuteReader()
    "Record successfully added to database" | Write-Host
}
Catch
{
    Write-Error $_.Exception.Message
}
   
# Close the connection
$connection.Close()