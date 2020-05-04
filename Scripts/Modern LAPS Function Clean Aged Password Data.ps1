using namespace System.Net
using namespace System.Data
using namespace System.Data.SqlClient

param($Timer)

# Maximum number of days to keep password history for. Anything older that this will be cleaned out.
$MaxAge = 90

# The 'IsPastDue' property is 'true' when the current function invocation is later than scheduled.
if ($Timer.IsPastDue) {
    Write-Host "Function is running late!"
}

# Output basic info about this execution
Write-Host "Beginning deletion of aged password data"

# Retrieve some variables
$MSI_ENDPOINT = [System.Environment]::GetEnvironmentVariable("MSI_ENDPOINT")
$MSI_SECRET = [System.Environment]::GetEnvironmentVariable("MSI_SECRET")
$ConnectionString = [System.Environment]::GetEnvironmentVariable("SQL Connection String")

# Obtain access token for function app managed identity for database audience
$tokenAuthURI = "$MSI_ENDPOINT`?resource=https://database.windows.net/&api-version=2017-09-01"
$tokenResponse = Invoke-RestMethod -Method Get -Headers @{"Secret"="$MSI_SECRET"} -Uri $tokenAuthURI
$accessToken = $tokenResponse.access_token

# SQL Query
$Query = "
Delete from [dbo].[LocalAdminPasswords]
Where DATEDIFF(day,PasswordRotationDateUTC,GETUTCDATE()) > $MaxAge
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
    "Success" | Out-Host
}
Catch
{
    Write-Error $_.Exception.Message
}
   
# Close the connection
$connection.Close()