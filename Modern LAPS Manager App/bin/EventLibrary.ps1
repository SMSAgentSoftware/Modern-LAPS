#############################
##                         ##
## Defines event handlers  ##
##                         ##
#############################

# Bring the main window to the front once loaded
$UI.Window.Add_Loaded({
    $This.Activate()
})

# Minimize window
$UI.WinMin.Add_Click({
    $UI.Window.WindowState = [System.Windows.WindowState]::Minimized
})

# Close window
$UI.WinClose.Add_Click({
    $UI.Window.Close()
})

# Window dragmove
$UI.Window.Add_MouseLeftButtonDown({ 
    $UI.Window.DragMove()
})

# Combo selection changed
$UI.Combo.Add_SelectionChanged({
    If ($This.SelectedValue -eq "Serial Number")
    {
        $UI.DataSource[1] = "Enter the serial number"
        $UI.SearchBox.Text = ""
    }
    If ($This.SelectedValue -eq "ComputerName")
    {
        $UI.DataSource[1] = "Enter the computer name"
        $UI.SearchBox.Text = ""
    }
})

# Search button clicked
$UI.SearchButton.Add_Click({

    $UI.DataSource[2] = $null
    $UI.DataSource[3] = ""

    If ($UI.SearchBox.Text.Length -lt 4)
    {
        If ($UI.Combo.SelectedIndex -eq 0)
        {
            $text = "Please enter a valid computer name in the search box!"
        }
        If ($UI.Combo.SelectedIndex -eq 1)
        {
            $text = "Please enter a valid serial number in the search box!"
        }
        $mds = [MahApps.Metro.Controls.Dialogs.MessageDialogStyle]::Affirmative
        $ColourScheme = [MahApps.Metro.Controls.Dialogs.MetroDialogColorScheme]::Accented
        $settings = New-Object MahApps.Metro.Controls.Dialogs.MetroDialogSettings
        $settings.ColorScheme = $ColourScheme
        $result = [MahApps.Metro.Controls.Dialogs.DialogManager]::ShowModalMessageExternal($UI.Window,"Oh dear!",$Text,$mds,$settings)
        Return
    }

    $Result = Get-SecureRegistryKeys
    If ($Result -eq 0)
    {
        $UI.DataSource[10] = "True"

        # Main code to run in background job
        $Code = {
            # Always declare as parameters any variables passed to the background job in the same order
            Param($UI,$SearchField,$SearchText)

            # Set TLS to 1.2 for secure transfer
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

            $Result1 = Get-AuthTokens
            If ($Result1 -eq 0)
            {
                $Result2 = Get-VaultKeys 
            }
            Else
            {
                Return
            }            
            If ($Result2 -eq 0)
            {
                Get-LocalAdminPassword -SearchField $SearchField -SearchText $SearchText
            }
            Else
            {
                Return
            }
        }

        $SearchField = $UI.Combo.SelectedValue 
        $SearchText = $UI.SearchBox.Text

        # Start a background job
        $Job = [BackgroundJob]::New($Code,@($UI,$SearchField,$SearchText),@("Function:\Get-LocalAdminPassword","Function:\Get-AuthTokens","Function:\Get-VaultKeys"))
        $UI.Jobs += $Job
        $Job.Start()  
    }
    Else
    {
        Return
    }

})

# Rotate password button clicked
$UI.RotateButton.Add_Click({

    $ComputerName = $UI.DataGrid.SelectedItem.ComputerName

    $Result = Show-AlternateCredentialsWindow
    If ($Result)
    {
        $UI.DataSource[10] = "True"
            
        # Main code to run in background job
        $Code = {
            # Always declare as parameters any variables passed to the background job in the same order
            Param($UI,$ComputerName)
            Rotate-LocalAdminPassword -ComputerName $ComputerName
        }

        # Start a background job
        $Job = [BackgroundJob]::New($Code,@($UI,$ComputerName),@("Function:\Rotate-LocalAdminPassword"))
        $UI.Jobs += $Job
        $Job.Start()               
    }

})

# Datagrid selection changed
$UI.DataGrid.Add_SelectionChanged({
    If ($UI.DataGrid.SelectedIndex -ne -1)
    {
        # Try Active encryption key first
        Try
        {
            $DecryptedPassword = Decrypt-Data -Key $UI.DataSource[5] -IVector $UI.DataSource[6] -Data $UI.DataGrid.SelectedItem.Password -ErrorAction Stop
            $UI.DataSource[3] = $DecryptedPassword
        }
        Catch
        {
            # Fallback to previous encryption key
            Try
            {
                $DecryptedPassword = Decrypt-Data -Key $UI.DataSource[28] -IVector $UI.DataSource[29] -Data $UI.DataGrid.SelectedItem.Password -ErrorAction Stop
                $UI.DataSource[3] = $DecryptedPassword
            }
            Catch
            {
                $text = "Could not decrypt password using either the active or previous encryption keys."
                $mds = [MahApps.Metro.Controls.Dialogs.MessageDialogStyle]::Affirmative
                $ColourScheme = [MahApps.Metro.Controls.Dialogs.MetroDialogColorScheme]::Accented
                $settings = New-Object MahApps.Metro.Controls.Dialogs.MetroDialogSettings
                $settings.ColorScheme = $ColourScheme
                $result = [MahApps.Metro.Controls.Dialogs.DialogManager]::ShowModalMessageExternal($UI.Window,"Oh dear!",$Text,$mds,$settings)
            }
        }
    }
})