using namespace System.Net
using namespace System.Data
using namespace System.Data.SqlClient

param($Request, $TriggerMetadata)

# Acknowledge the request
Write-Host "Received a request to access the SQL database."

# Get the connection string
$ConnectionString = [System.Environment]::GetEnvironmentVariable("SQL Connection String")

# Get the access token and query
$AccessToken = $Request.Query.AccessToken
$Query = $Request.Query.Query

# Make sure we have both the access token and the query. If not, send a BadRequest code.
if ($AccessToken -and $Query) {
    $status = [HttpStatusCode]::OK

    # Query the database
    Try
    {
        $connection = New-Object -TypeName System.Data.SqlClient.SqlConnection
        $connection.ConnectionString = $ConnectionString
        $connection.AccessToken = $AccessToken
        $connection.Open()  
        $command = $connection.CreateCommand()
        $command.CommandText = $Query
        $reader = $command.ExecuteReader()
        $table = New-Object -TypeName 'System.Data.DataTable'
        $table.Load($reader)
        $connection.Close()
        $Result = $table | ConvertTo-Json 
    }
    Catch
    {
        $Result = $_.Exception.Message
        Write-Error $_.Exception.Message
    }
}
else {
    $status = [HttpStatusCode]::BadRequest
    $Result = "Please pass an access token and a SQL query on the query string."
}

# Send the repsonse
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = $status
    Body = $Result
})