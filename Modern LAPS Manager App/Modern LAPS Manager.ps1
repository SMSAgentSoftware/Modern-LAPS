##########################################################################
##                                                                      ##
##                        MODERN LAPS MANAGER                           ##
##                                                                      ##
## Author:      Trevor Jones                                            ##
## Blog:        smsagent.blog                                           ##
##                                                                      ##
##########################################################################


# Set the location we are running from
$script:Source = $PSScriptRoot

# Load the function library
. "$Source\bin\FunctionLibrary.ps1"

# Load the required assemblies
Add-Type -AssemblyName PresentationFramework,PresentationCore,WindowsBase
Add-Type -Path "$Source\bin\System.Windows.Interactivity.dll"
Add-Type -Path "$Source\bin\ControlzEx.dll"
Add-Type -Path "$Source\bin\MahApps.Metro.dll"
Add-Type -Path "$Source\bin\MahApps.Metro.IconPacks.FontAwesome.dll"

# Load the main window XAML code
[XML]$Xaml = [System.IO.File]::ReadAllLines("$Source\Xaml\App.xaml") 

# Create a synchronized hash table and add the WPF window and its named elements to it
$UI = [System.Collections.Hashtable]::Synchronized(@{})
$UI.Window = [Windows.Markup.XamlReader]::Load((New-Object -TypeName System.Xml.XmlNodeReader -ArgumentList $xaml))
$xaml.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]") | 
    ForEach-Object -Process {
        $UI.$($_.Name) = $UI.Window.FindName($_.Name)
    }

# Hold the background jobs here. Useful for querying the streams for any errors.
$UI.Jobs = @()
# View the error stream for the first background job, for example
#$UI.Jobs[0].PSInstance.Streams.Error

# Load in the other code libraries.
. "$Source\bin\ClassLibrary.ps1"
. "$Source\bin\EventLibrary.ps1"

# OC for data binding source #4,8,9,18 not used
$UI.DataSource = New-Object System.Collections.ObjectModel.ObservableCollection[Object]
$UI.DataSource.Add(@("ComputerName","Serial Number"))                                                         # [0] Combo Values
$UI.DataSource.Add("Select which field to search with")                                                       # [1] SearchBox Watermark
$UI.DataSource.Add($null)                                                                                     # [2] DataGrid ItemsSource
$UI.DataSource.Add($null)                                                                                     # [3] Recovery Key Text
$UI.DataSource.Add($null)                                                                                     # [4] Connection String
$UI.DataSource.Add($null)                                                                                     # [5] Encryption Key
$UI.DataSource.Add($null)                                                                                     # [6] Encryption IV
$UI.DataSource.Add($source)                                                                                   # [7] Script source
$UI.DataSource.Add($null)                                                                                     # [8] Username
$UI.DataSource.Add($null)                                                                                     # [9] Password
$UI.DataSource.Add($false)                                                                                    # [10] Progress bar indeterminate
$UI.DataSource.Add($false)                                                                                    # [11] Password Rotation Button enabled
$UI.DataSource.Add($null)                                                                                     # [12] UI.Datagrid.SelectedIndex
$UI.DataSource.Add($null)                                                                                     # [13] Alternate username
$UI.DataSource.Add($null)                                                                                     # [14] Alternate password
$UI.DataSource.Add($null)                                                                                     # [15] CI Unique ID of local admin password compliance baseline in ConfigMgr
$UI.DataSource.Add($null)                                                                                     # [16] Client App ID
$UI.DataSource.Add($null)                                                                                     # [17] Function URL
$UI.DataSource.Add($null)                                                                                     # [18] x-ms-version
$UI.DataSource.Add($null)                                                                                     # [19] PreviousEncryptionKeyIVName
$UI.DataSource.Add($null)                                                                                     # [20] PreviousEncryptionKeyName
$UI.DataSource.Add($null)                                                                                     # [21] ActiveEncryptionKeyIVName
$UI.DataSource.Add($null)                                                                                     # [22] ActiveEncryptionKeyName
$UI.DataSource.Add($null)                                                                                     # [23] ClientAppRedirectURI
$UI.DataSource.Add($null)                                                                                     # [24] KeyVaultURL
$UI.DataSource.Add($null)                                                                                     # [25] BaselineCIUniqueIDName
$UI.DataSource.Add($null)                                                                                     # [26] SQL Auth token
$UI.DataSource.Add($null)                                                                                     # [27] Vault Auth token
$UI.DataSource.Add($null)                                                                                     # [28] Previous Encryption key
$UI.DataSource.Add($null)                                                                                     # [29] Previous Encryption IV
$UI.DataSource.Add($null)                                                                                     # [30] Key Vault API version

# Set the datacontext of the window to the OC for databinding
$UI.Window.DataContext = $UI.DataSource

# Set the initial selection for the combo box
$UI.Combo.SelectedIndex = 0

# Display the main window
# If code is running in ISE, use ShowDialog()...
if ($psISE)
{
    $null = $UI.window.Dispatcher.InvokeAsync{$UI.window.ShowDialog()}.Wait()
}
# ...otherwise run as an application
Else
{
    # Hide the PowerShell console window
    $windowcode = '[DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);'
    $asyncwindow = Add-Type -MemberDefinition $windowcode -Name Win32ShowWindowAsync -Namespace Win32Functions -PassThru
    $null = $asyncwindow::ShowWindowAsync((Get-Process -PID $pid).MainWindowHandle, 0)
    
    # Run the main window in an application
    $app = New-Object -TypeName Windows.Application
    $app.Properties
    $app.Run($UI.Window)
}