####################################
##                                ##
## Contains PowerShell functions  ##
##                                ##
####################################

# Function to decrypt the recovery password
Function script:Decrypt-Data {
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

# Function to get Local Admin Password from SQL database
Function Get-LocalAdminPassword {

    param($SearchField,$SearchText)

    If ($SearchField -eq "ComputerName")
    {
        $Query = "
            Select *
            From [dbo].[LocalAdminPasswords]
            Where ComputerName like '%$SearchText%'
        "
    }
    If ($SearchField -eq "Serial Number")
    {
        $Query = "
            Select *
            From [dbo].[LocalAdminPasswords]
            Where SerialNumber like '%$SearchText%'
        "
    }

    # Trigger Azure Function app to get data from SQL
    #$FunctionURL = $UI.DataSource[17] + "&AccessToken=$($UI.DataSource[26])&Query=$Query" # for GET requests
    $FunctionURL = $UI.DataSource[17] # for POST requests
    # Add 'https://' to URI if not present - POST request requires this
    If ($FunctionURL.StartsWith('https://'))
    {}
    Else
    {
        $FunctionURL = "https://" + $FunctionURL
    }

# Pass the access token and query in JSON format
$Body = @"
{
    "AccessToken": "$($UI.DataSource[26])",
    "Query": "$Query"
}   
"@

    Try
    {
        $Response = Invoke-WebRequest -Uri $FunctionURL -Method POST -Body $Body -ContentType "application/json" -ErrorAction Stop -ErrorVariable ResponseError
    }
    Catch
    {
        $UI.DataSource[10] = $false
        $UI.Window.Dispatcher.Invoke({
            $text = "Error calling Azure function. You may have entered an invalid search entry, or there is no data available for it.$([System.Environment]::NewLine)Error detail: $_"
            $mds = [MahApps.Metro.Controls.Dialogs.MessageDialogStyle]::Affirmative
            $ColourScheme = [MahApps.Metro.Controls.Dialogs.MetroDialogColorScheme]::Accented
            $settings = New-Object MahApps.Metro.Controls.Dialogs.MetroDialogSettings
            $settings.ColorScheme = $ColourScheme
            $result = [MahApps.Metro.Controls.Dialogs.DialogManager]::ShowModalMessageExternal($UI.Window,"Oh dear!",$Text,$mds,$settings)
        })
        Return
    }
    Try
    {
        $ConvertedJson = $Response.Content | ConvertFrom-Json -ErrorAction Stop
        $LocalDateTimePattern = (Get-Culture -ErrorAction Stop).DateTimeFormat.FullDateTimePattern
        $Datatable = New-Object System.Data.Datatable
        [void]$Datatable.Columns.Add("RecordID",[Double])
        [void]$Datatable.Columns.Add("ComputerName",[System.String])
        [void]$Datatable.Columns.Add("SerialNumber",[System.String])
        [void]$Datatable.Columns.Add("PasswordRotationDateUTC",[System.String])
        [void]$Datatable.Columns.Add("PasswordRotationDateLocal",[System.String])
        [void]$Datatable.Columns.Add("LocalTimezone",[System.String])
        [void]$Datatable.Columns.Add("IsDaylightSaving",[System.String])
        [void]$Datatable.Columns.Add("UTCOffset",[Double])
        [void]$Datatable.Columns.Add("UploadDateUTC",[System.String])
        [void]$Datatable.Columns.Add("NextPasswordRotationDateUTC",[System.String])
        [void]$Datatable.Columns.Add("Password",[System.String])
        Foreach ($Item in $ConvertedJson)
        {
            [void]$Datatable.Rows.Add(
                $Item.RecordId,
                $Item.ComputerName,
                $Item.SerialNumber,
                ($Item.PasswordRotationDateUTC | Get-Date -Format $LocalDateTimePattern).ToString(),
                ($Item.PasswordRotationDateLocal | Get-Date -Format $LocalDateTimePattern).ToString(),
                $Item.LocalTimezone,
                $Item.IsDaylightSaving,
                $Item.UTCOffset,
                ($Item.UploadDateUTC | Get-Date -Format $LocalDateTimePattern).ToString(),
                ($Item.NextPasswordRotationDateUTC | Get-Date -Format $LocalDateTimePattern).ToString(),
                $Item.Password
            )
        }

        $Datatable.DefaultView.Sort = "RecordID desc"
        [System.Data.DataTable]$Table = $Datatable.DefaultView.ToTable()
    }
    Catch
    {
        $UI.DataSource[10] = $false
        $UI.Window.Dispatcher.Invoke({
            $text = "Unable to convert data to datatable format for display.$([System.Environment]::NewLine)Error detail: $_"
            $mds = [MahApps.Metro.Controls.Dialogs.MessageDialogStyle]::Affirmative
            $ColourScheme = [MahApps.Metro.Controls.Dialogs.MetroDialogColorScheme]::Accented
            $settings = New-Object MahApps.Metro.Controls.Dialogs.MetroDialogSettings
            $settings.ColorScheme = $ColourScheme
            $result = [MahApps.Metro.Controls.Dialogs.DialogManager]::ShowModalMessageExternal($UI.Window,"Oh dear!",$Text,$mds,$settings)
        })
        Return
    }
             
    $UI.DataSource[2] = $table
    $UI.DataSource[12] = 0

    If ($Table.Rows.Count -eq 0)
    {
        $UI.DataSource[10] = $false
        $text = "No results were found!"
        $mds = [MahApps.Metro.Controls.Dialogs.MessageDialogStyle]::Affirmative
        $ColourScheme = [MahApps.Metro.Controls.Dialogs.MetroDialogColorScheme]::Accented
        $settings = New-Object MahApps.Metro.Controls.Dialogs.MetroDialogSettings
        $settings.ColorScheme = $ColourScheme
        $result = [MahApps.Metro.Controls.Dialogs.DialogManager]::ShowModalMessageExternal($UI.Window,"Oh dear!",$Text,$mds,$settings)
        Return
    }

    $UI.DataSource[10] = $False
    $UI.DataSource[11] = "True"        
        
}

# Function to rotate the local administrator password
Function Rotate-LocalAdminPassword {
    Param($ComputerName)

    $CI_UniqueID = $UI.DataSource[15]
    $Username = $UI.DataSource[13]
    $Password = $UI.DataSource[14]

    # Create credential object if required
    If ($Username -and $Password)
    {
        [securestring]$secStringPassword = ConvertTo-SecureString $Password -AsPlainText -Force
        [pscredential]$Credentials = New-Object System.Management.Automation.PSCredential ($Username, $secStringPassword)
    }

    # Remove the registry key for the next password rotation date
    If ($Credentials)
    {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {Remove-ItemProperty -Path "HKLM:\SOFTWARE\SMSAgent\Modern LAPS" -Name NextPasswordRotationDateUTC -Force} -Credential $Credentials -ErrorVariable WMIResult -ErrorAction Continue
    }
    Else
    {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {Remove-ItemProperty -Path "HKLM:\SOFTWARE\SMSAgent\Modern LAPS" -Name NextPasswordRotationDateUTC -Force} -ErrorVariable WMIResult -ErrorAction Continue
    }
    If ($WMIResult)
    {
        $UI.DataSource[10] = $false
        $UI.Window.Dispatcher.Invoke({
            $text = "Could not rotate local admin password. There was an error accessing the registry on the remote workstation.$([System.Environment]::NewLine)Error details: $($WMIResult[0].Exception.Message)"
            $mds = [MahApps.Metro.Controls.Dialogs.MessageDialogStyle]::Affirmative
            $ColourScheme = [MahApps.Metro.Controls.Dialogs.MetroDialogColorScheme]::Accented
            $settings = New-Object MahApps.Metro.Controls.Dialogs.MetroDialogSettings
            $settings.ColorScheme = $ColourScheme
            $result = [MahApps.Metro.Controls.Dialogs.DialogManager]::ShowModalMessageExternal($UI.Window,"Oh dear!",$Text,$mds,$settings)
        })
        Return
    }
    If ($Credentials)
    {
        Try
        {
            $CimSession = New-CimSession -ComputerName $ComputerName -Credential $Credentials -ErrorAction Stop
            $Instance = Get-CimInstance -CimSession $CimSession -Namespace ROOT\ccm\dcm -ClassName SMS_DesiredConfiguration -Filter "Name='$CI_UniqueID'" -OperationTimeoutSec 10 -ErrorVariable CIMResult -ErrorAction Continue
        }
        Catch
        {
            $UI.DataSource[10] = $false
            $UI.Window.Dispatcher.Invoke({
                $text = "Could not access WMI on the target workstation. The local administrator password will still be rotated within a few hours when the next scheduled baseline evaluation occurs.$([System.Environment]::NewLine)Error details: $_)"
                $mds = [MahApps.Metro.Controls.Dialogs.MessageDialogStyle]::Affirmative
                $ColourScheme = [MahApps.Metro.Controls.Dialogs.MetroDialogColorScheme]::Accented
                $settings = New-Object MahApps.Metro.Controls.Dialogs.MetroDialogSettings
                $settings.ColorScheme = $ColourScheme
                $result = [MahApps.Metro.Controls.Dialogs.DialogManager]::ShowModalMessageExternal($UI.Window,"Oh dear!",$Text,$mds,$settings)
            })
            
            If ($CimSession)
            {
                Remove-CimSession -CimSession $CimSession
            }
            Return
        }
    }
    Else
    {
        $Instance = Get-CimInstance -ComputerName $ComputerName -Namespace ROOT\ccm\dcm -ClassName SMS_DesiredConfiguration -Filter "Name='$CI_UniqueID'" -OperationTimeoutSec 10 -ErrorVariable CIMResult -ErrorAction Continue
    }
    If ($CIMResult)
    {
        $UI.DataSource[10] = $false
        $UI.Window.Dispatcher.Invoke({
            $text = "Could not access WMI on the target workstation. The local administrator password will still be rotated within a few hours when the next scheduled baseline evaluation occurs.$([System.Environment]::NewLine)Error details: $($CIMResult[0].Exception.Message)"
            $mds = [MahApps.Metro.Controls.Dialogs.MessageDialogStyle]::Affirmative
            $ColourScheme = [MahApps.Metro.Controls.Dialogs.MetroDialogColorScheme]::Accented
            $settings = New-Object MahApps.Metro.Controls.Dialogs.MetroDialogSettings
            $settings.ColorScheme = $ColourScheme
            $result = [MahApps.Metro.Controls.Dialogs.DialogManager]::ShowModalMessageExternal($UI.Window,"Oh dear!",$Text,$mds,$settings)
        })
        If ($CimSession)
        {
            Remove-CimSession -CimSession $CimSession
        }
        Return
    }

    If ($Instance -eq $null)
    {
        $UI.DataSource[10] = $false
        $UI.Window.Dispatcher.Invoke({
            $text = "The compliance baseline could not be identified on the target workstation."
            $mds = [MahApps.Metro.Controls.Dialogs.MessageDialogStyle]::Affirmative
            $ColourScheme = [MahApps.Metro.Controls.Dialogs.MetroDialogColorScheme]::Accented
            $settings = New-Object MahApps.Metro.Controls.Dialogs.MetroDialogSettings
            $settings.ColorScheme = $ColourScheme
            $result = [MahApps.Metro.Controls.Dialogs.DialogManager]::ShowModalMessageExternal($UI.Window,"Oh dear!",$Text,$mds,$settings)
        })
        If ($CimSession)
        {
            Remove-CimSession -CimSession $CimSession
        }
        Return
    }

    $Arguments = @{
        Name = $Instance.Name
        Version = $Instance.Version
        IsMachineTarget = [bool]$Instance.IsMachineTarget
        IsEnforced = $True
        PolicyType = [Uint32]$Instance.PolicyType
    }
    If ($CimSession)
    {
        $Result = Invoke-CimMethod -CimSession $CimSession -Namespace ROOT\ccm\dcm -ClassName SMS_DesiredConfiguration -MethodName "TriggerEvaluation" -Arguments $Arguments -ErrorVariable CIMMethodResult -ErrorAction Continue -OperationTimeoutSec 30
    }
    Else
    {
        $Result = Invoke-CimMethod -ComputerName $ComputerName -Namespace ROOT\ccm\dcm -ClassName SMS_DesiredConfiguration -MethodName "TriggerEvaluation" -Arguments $Arguments -ErrorVariable CIMMethodResult -ErrorAction Continue -OperationTimeoutSec 30
    }
    If ($CIMMethodResult)
    {
        $UI.DataSource[10] = $false
        $UI.Window.Dispatcher.Invoke({
            $text = "Could not trigger the baseline evaluation. The local administrator password should still be rotated within a few hours when the next scheduled baseline evaluation occurs.$([System.Environment]::NewLine)Error details: $($CIMMethodResult[0].Exception.Message)"
            $mds = [MahApps.Metro.Controls.Dialogs.MessageDialogStyle]::Affirmative
            $ColourScheme = [MahApps.Metro.Controls.Dialogs.MetroDialogColorScheme]::Accented
            $settings = New-Object MahApps.Metro.Controls.Dialogs.MetroDialogSettings
            $settings.ColorScheme = $ColourScheme
            $result = [MahApps.Metro.Controls.Dialogs.DialogManager]::ShowModalMessageExternal($UI.Window,"Oh dear!",$Text,$mds,$settings)
        })
        If ($CimSession)
        {
            Remove-CimSession -CimSession $CimSession
        }
        Return 
    }

    If ($CimSession)
    {
        Remove-CimSession -CimSession $CimSession
    }

    $UI.DataSource[10] = $false
    $UI.Window.Dispatcher.Invoke({
        $text = "The local administrator password on $Computername was successfully rotated."
        $mds = [MahApps.Metro.Controls.Dialogs.MessageDialogStyle]::Affirmative
        $ColourScheme = [MahApps.Metro.Controls.Dialogs.MetroDialogColorScheme]::Accented
        $settings = New-Object MahApps.Metro.Controls.Dialogs.MetroDialogSettings
        $settings.ColorScheme = $ColourScheme
        $result = [MahApps.Metro.Controls.Dialogs.DialogManager]::ShowModalMessageExternal($UI.Window,"Score!",$Text,$mds,$settings)
    })
}

# Function to display alternate credentials window
Function Show-AlternateCredentialsWindow {
    
    [XML]$Xaml = [System.IO.File]::ReadAllLines("$Source\Xaml\AlternateCredentials.xaml") 
    $UI.AlternateCredentialsWindow = [Windows.Markup.XamlReader]::Load((New-Object -TypeName System.Xml.XmlNodeReader -ArgumentList $xaml))
    $xaml.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]") | 
        ForEach-Object -Process {
            $UI.$($_.Name) = $UI.AlternateCredentialsWindow.FindName($_.Name)
        }
    $UI.AlternateCredentialsWindow.Owner = $UI.Window

    $UI.OKButton.Add_Click({
        $UI.DataSource[13] = $UI.AltUsernameBox.Text
        $UI.DataSource[14] = $UI.AltPasswordBox.Password
        $UI.AlternateCredentialsWindow.DialogResult=$true
        $UI.AlternateCredentialsWindow.Close()
    })

    $UI.AltPasswordBox.Add_KeyDown({
        if ($_.Key -eq 'Return')
        {
            $UI.DataSource[13] = $UI.AltUsernameBox.Text
            $UI.DataSource[14] = $UI.AltPasswordBox.Password
            $UI.AlternateCredentialsWindow.DialogResult=$true
            $UI.AlternateCredentialsWindow.Close()
        }
    })

    $UI.AltCredWinClose.Add_Click({
        
        $UI.AlternateCredentialsWindow.Close()
    })
    
    $UI.AlternateCredentialsWindow.ShowDialog()
}

# Function to read and convert the required app values from the registry
Function Get-SecureRegistryKeys {
    
    # Reg key names
    $RegBase = "HKCU"
    $RegBranch = "Software"
    $AppVendor = "SMSAgent"
    $AppName = "Modern LAPS Manager"

    $DataHash = @{
        KeyVaultURL = ""
        KeyVaultAPIVersion = ""
        ActiveEncryptionKeyName = ""
        ActiveEncryptionKeyIVName = ""
        PreviousEncryptionKeyName = ""
        PreviousEncryptionKeyIVName = ""
        BaselineCIUniqueIDName = ""
        ClientAppID = ""
        ClientAppRedirectURI = ""
        FunctionURL = ""
    }
    $Array = $DataHash.GetEnumerator().Name

    Foreach ($Key in $Array)
    {
        Try
        {
            $SS = Get-ItemProperty -Path "$RegBase`:\$RegBranch\$AppVendor\$AppName" -Name $Key | Select -ExpandProperty $Key | ConvertTo-SecureString -ErrorAction Stop
            $Credential = [PSCredential]::new("Data",$SS)
            $DataHash[$key] = $Credential.GetNetworkCredential().Password
            Remove-Variable Credential -Force
        }
        Catch
        {
            $text = "The app was unable to locate or securely convert the required registry values from the current user registry. Ensure they have been populated before using the app.$([System.Environment]::NewLine)Error details: $_"
            $mds = [MahApps.Metro.Controls.Dialogs.MessageDialogStyle]::Affirmative
            $ColourScheme = [MahApps.Metro.Controls.Dialogs.MetroDialogColorScheme]::Accented
            $settings = New-Object MahApps.Metro.Controls.Dialogs.MetroDialogSettings
            $settings.ColorScheme = $ColourScheme
            $result = [MahApps.Metro.Controls.Dialogs.DialogManager]::ShowModalMessageExternal($UI.Window,"Oh dear!",$Text,$mds,$settings)
            Return
        }
    }

    $UI.DataSource[16] = $DataHash["ClientAppID"]
    $UI.DataSource[17] = $DataHash["FunctionURL"]
    $UI.DataSource[19] = $DataHash["PreviousEncryptionKeyIVName"]
    $UI.DataSource[20] = $DataHash["PreviousEncryptionKeyName"]
    $UI.DataSource[21] = $DataHash["ActiveEncryptionKeyIVName"]
    $UI.DataSource[22] = $DataHash["ActiveEncryptionKeyName"]
    $UI.DataSource[23] = $DataHash["ClientAppRedirectURI"]
    $UI.DataSource[24] = $DataHash["KeyVaultURL"]
    $UI.DataSource[25] = $DataHash["BaselineCIUniqueIDName"]
    $UI.DataSource[30] = $DataHash["KeyVaultAPIVersion"]

    Return 0
}

# Function to get auth tokens from Azure 
Function Get-AuthTokens {
    
    # Prepare ADAL
    Try
    {
        Add-Type -Path "$($UI.DataSource[7])\bin\Microsoft.IdentityModel.Clients.ActiveDirectory.dll" -ErrorAction Stop
        $AuthenticationURI = "https://login.microsoftonline.com/common"
        $AuthenticationContext = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext($AuthenticationURI)       
        $PlatformParams = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters("Auto")
    }
    Catch
    {
        $UI.DataSource[10] = $false
        $UI.Window.Dispatcher.Invoke({
            $text = "Unable to create an authentication context using the Microsoft Active Directory Authentication Library.$([System.Environment]::NewLine)Error details: $_"
            $mds = [MahApps.Metro.Controls.Dialogs.MessageDialogStyle]::Affirmative
            $ColourScheme = [MahApps.Metro.Controls.Dialogs.MetroDialogColorScheme]::Accented
            $settings = New-Object MahApps.Metro.Controls.Dialogs.MetroDialogSettings
            $settings.ColorScheme = $ColourScheme
            $result = [MahApps.Metro.Controls.Dialogs.DialogManager]::ShowModalMessageExternal($UI.Window,"Oh dear!",$Text,$mds,$settings)
        })
        Return
    }

    $ClientID = $UI.DataSource[16] 
    $RedirectURI = $UI.DataSource[23]
    
    # For Azure SQL DB   
    $Resource = "https://database.windows.net/"
    Try
    {
        $Response = $AuthenticationContext.AcquireTokenAsync($Resource,$clientID,$RedirectURI,$PlatformParams)
        If ($Response.IsFaulted)
        {
            $UI.DataSource[10] = $false
            $UI.Window.Dispatcher.Invoke({
                $text = "Unable to obtain an authentication token for Azure SQL Database. Ensure you have been granted the required permissions.$([System.Environment]::NewLine)Error details: $($Response.Exception.InnerException.Message)"
                $mds = [MahApps.Metro.Controls.Dialogs.MessageDialogStyle]::Affirmative
                $ColourScheme = [MahApps.Metro.Controls.Dialogs.MetroDialogColorScheme]::Accented
                $settings = New-Object MahApps.Metro.Controls.Dialogs.MetroDialogSettings
                $settings.ColorScheme = $ColourScheme
                $result = [MahApps.Metro.Controls.Dialogs.DialogManager]::ShowModalMessageExternal($UI.Window,"Oh dear!",$Text,$mds,$settings)
            })
            Return
        }
        Else
        {
            $UI.DataSource[26] = $Response.Result.AccessToken
        }        
    }
    Catch
    {
        $UI.DataSource[10] = $false
        $UI.Window.Dispatcher.Invoke({
            $text = "Unable to obtain an authentication token for Azure SQL Database. Ensure you have been granted the required permissions.$([System.Environment]::NewLine)Error details: $_"
            $mds = [MahApps.Metro.Controls.Dialogs.MessageDialogStyle]::Affirmative
            $ColourScheme = [MahApps.Metro.Controls.Dialogs.MetroDialogColorScheme]::Accented
            $settings = New-Object MahApps.Metro.Controls.Dialogs.MetroDialogSettings
            $settings.ColorScheme = $ColourScheme
            $result = [MahApps.Metro.Controls.Dialogs.DialogManager]::ShowModalMessageExternal($UI.Window,"Oh dear!",$Text,$mds,$settings)
        })
        Return
    }

    # For Azure Key vault
    $Resource = "https://vault.azure.net"
    Try
    {
        $Response = $AuthenticationContext.AcquireTokenAsync($Resource,$clientID,$RedirectURI,$PlatformParams)
        If ($Response.IsFaulted)
        {
            $UI.DataSource[10] = $false
            $UI.Window.Dispatcher.Invoke({
                $text = "Faulted: Unable to obtain an authentication token for Azure Key Vault. Ensure you have been granted the required permissions.$([System.Environment]::NewLine)Error details: $($Response.Exception.InnerException.Message)"
                $mds = [MahApps.Metro.Controls.Dialogs.MessageDialogStyle]::Affirmative
                $ColourScheme = [MahApps.Metro.Controls.Dialogs.MetroDialogColorScheme]::Accented
                $settings = New-Object MahApps.Metro.Controls.Dialogs.MetroDialogSettings
                $settings.ColorScheme = $ColourScheme
                $result = [MahApps.Metro.Controls.Dialogs.DialogManager]::ShowModalMessageExternal($UI.Window,"Oh dear!",$Text,$mds,$settings)
            })
            Return
        }
        Else
        {
            $UI.DataSource[27] = $Response.Result.AccessToken
        }  
    }
    Catch
    {
        $UI.DataSource[10] = $false
        $UI.Window.Dispatcher.Invoke({
            $text = "Unable to obtain an authentication token for Azure Key Vault. Ensure you have been granted the required permissions.$([System.Environment]::NewLine)Error details: $_"
            $mds = [MahApps.Metro.Controls.Dialogs.MessageDialogStyle]::Affirmative
            $ColourScheme = [MahApps.Metro.Controls.Dialogs.MetroDialogColorScheme]::Accented
            $settings = New-Object MahApps.Metro.Controls.Dialogs.MetroDialogSettings
            $settings.ColorScheme = $ColourScheme
            $result = [MahApps.Metro.Controls.Dialogs.DialogManager]::ShowModalMessageExternal($UI.Window,"Oh dear!",$Text,$mds,$settings)
        })
        Return
    }

    Return 0  
}

# Function to obtain secret values from Azure Key Vault
Function Get-VaultKeys {

    $Headers = @{
        'x-ms-date' = $([datetime]::UtcNow.ToString("R"))
        Authorization = "Bearer $($UI.Datasource[27])"
    }

    $VaultURL = $UI.DataSource[24]
    $APIVersion = $UI.DataSource[30]

    If ($VaultURL.EndsWith('/'))
    {
        $VaultURL = $VaultURL.TrimEnd('/')
    }

    # ActiveEncryptionKey
    $SecretURL = "$VaultURL/secrets/$($UI.DataSource[22])?$APIVersion"
    Try
    {
        $Response = Invoke-WebRequest -Uri $SecretURL -Headers $Headers -ErrorAction Stop
        $UI.Datasource[5] = ($Response.Content | ConvertFrom-Json -ErrorAction Stop).value
    }
    Catch
    {
        $UI.DataSource[10] = $false
        $UI.Window.Dispatcher.Invoke({
            $text = "Unable to obtain active encryption key from Azure Key Vault.$([System.Environment]::NewLine)Error details: $_"
            $mds = [MahApps.Metro.Controls.Dialogs.MessageDialogStyle]::Affirmative
            $ColourScheme = [MahApps.Metro.Controls.Dialogs.MetroDialogColorScheme]::Accented
            $settings = New-Object MahApps.Metro.Controls.Dialogs.MetroDialogSettings
            $settings.ColorScheme = $ColourScheme
            $result = [MahApps.Metro.Controls.Dialogs.DialogManager]::ShowModalMessageExternal($UI.Window,"Oh dear!",$Text,$mds,$settings)
        })
        Return
    }

    # ActiveEncryptionKeyIV
    $SecretURL = "$VaultURL/secrets/$($UI.DataSource[21])?$APIVersion"
    Try
    {
        $Response = Invoke-WebRequest -Uri $SecretURL -Headers $Headers -ErrorAction Stop
        $UI.Datasource[6] = ($Response.Content | ConvertFrom-Json -ErrorAction Stop).value
    }
    Catch
    {
        $UI.DataSource[10] = $false
        $UI.Window.Dispatcher.Invoke({
            $text = "Unable to obtain active encryption key initialization vector from Azure Key Vault.$([System.Environment]::NewLine)Error details: $_"
            $mds = [MahApps.Metro.Controls.Dialogs.MessageDialogStyle]::Affirmative
            $ColourScheme = [MahApps.Metro.Controls.Dialogs.MetroDialogColorScheme]::Accented
            $settings = New-Object MahApps.Metro.Controls.Dialogs.MetroDialogSettings
            $settings.ColorScheme = $ColourScheme
            $result = [MahApps.Metro.Controls.Dialogs.DialogManager]::ShowModalMessageExternal($UI.Window,"Oh dear!",$Text,$mds,$settings)
        })
        Return
    }

    # PreviousEncryptionKey
    $SecretURL = "$VaultURL/secrets/$($UI.DataSource[20])?$APIVersion"
    Try
    {
        $Response = Invoke-WebRequest -Uri $SecretURL -Headers $Headers -ErrorAction Stop
        $UI.Datasource[28] = ($Response.Content | ConvertFrom-Json -ErrorAction Stop).value
    }
    Catch
    {
        $UI.DataSource[10] = $false
        $UI.Window.Dispatcher.Invoke({
            $text = "Unable to obtain previous encryption key from Azure Key Vault.$([System.Environment]::NewLine)Error details: $_"
            $mds = [MahApps.Metro.Controls.Dialogs.MessageDialogStyle]::Affirmative
            $ColourScheme = [MahApps.Metro.Controls.Dialogs.MetroDialogColorScheme]::Accented
            $settings = New-Object MahApps.Metro.Controls.Dialogs.MetroDialogSettings
            $settings.ColorScheme = $ColourScheme
            $result = [MahApps.Metro.Controls.Dialogs.DialogManager]::ShowModalMessageExternal($UI.Window,"Oh dear!",$Text,$mds,$settings)
        })
        Return
    }

    # PreviousEncryptionKeyIV
    $SecretURL = "$VaultURL/secrets/$($UI.DataSource[19])?$APIVersion"
    Try
    {
        $Response = Invoke-WebRequest -Uri $SecretURL -Headers $Headers -ErrorAction Stop
        $UI.Datasource[29] = ($Response.Content | ConvertFrom-Json -ErrorAction Stop).value
    }
    Catch
    {
        $UI.DataSource[10] = $false
        $UI.Window.Dispatcher.Invoke({
            $text = "Unable to obtain previous encryption key initialization vector from Azure Key Vault.$([System.Environment]::NewLine)Error details: $_"
            $mds = [MahApps.Metro.Controls.Dialogs.MessageDialogStyle]::Affirmative
            $ColourScheme = [MahApps.Metro.Controls.Dialogs.MetroDialogColorScheme]::Accented
            $settings = New-Object MahApps.Metro.Controls.Dialogs.MetroDialogSettings
            $settings.ColorScheme = $ColourScheme
            $result = [MahApps.Metro.Controls.Dialogs.DialogManager]::ShowModalMessageExternal($UI.Window,"Oh dear!",$Text,$mds,$settings)
        })
        Return
    }

    # BaselineCIUniqueID
    $SecretURL = "$VaultURL/secrets/$($UI.DataSource[25])?$APIVersion"
    Try
    {
        $Response = Invoke-WebRequest -Uri $SecretURL -Headers $Headers -ErrorAction Stop
        $UI.Datasource[15] = ($Response.Content | ConvertFrom-Json -ErrorAction Stop).value
    }
    Catch
    {
        $UI.DataSource[10] = $false
        $UI.Window.Dispatcher.Invoke({
            $text = "Unable to obtain CI Unique ID for the ConfigMgr baseline from Azure Key Vault.$([System.Environment]::NewLine)Error details: $_"
            $mds = [MahApps.Metro.Controls.Dialogs.MessageDialogStyle]::Affirmative
            $ColourScheme = [MahApps.Metro.Controls.Dialogs.MetroDialogColorScheme]::Accented
            $settings = New-Object MahApps.Metro.Controls.Dialogs.MetroDialogSettings
            $settings.ColorScheme = $ColourScheme
            $result = [MahApps.Metro.Controls.Dialogs.DialogManager]::ShowModalMessageExternal($UI.Window,"Oh dear!",$Text,$mds,$settings)
        })
        Return
    }

    Return 0
}