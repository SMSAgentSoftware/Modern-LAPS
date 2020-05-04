# Trigger a manual rotation of the local administrator account password managed by Modern LAPS by triggering an evaluation of the configuration baseline

# Unique ID of the ConfigMgr baseline
$CI_UniqueID = "ScopeId_CD48B1CE-DAC9-1234-9985-867DD7776A1A/Baseline_abf2842f-8f9f-0dl3-b150-85d0f075c3b0"

# Remove the Next Password Rotation Date from the registry. The will cause the configuration baseline to rotate the password when next run.
Remove-ItemProperty -Path "HKLM:\SOFTWARE\SMSAgent\Modern LAPS" -Name NextPasswordRotationDateUTC -Force -ErrorVariable RegistryError -ErrorAction Stop
If ($RegistryError)
{
    Return $RegistryError
}

# Get the CimInstance
$Instance = Get-CimInstance -Namespace ROOT\ccm\dcm -ClassName SMS_DesiredConfiguration -Filter "Name='$CI_UniqueID'" -OperationTimeoutSec 10 -ErrorVariable CIMError -ErrorAction Stop
If ($CIMError)
{
    Return $CIMError
}

# Trigger the evaluation
# Don't set the 'IsMachineTarget' parameter when using Run Script otherwise the client will error that SYSTEM context is an invalid user
$Arguments = @{
    Name = $Instance.Name
    Version = $Instance.Version
}
$Result = Invoke-CimMethod -Namespace ROOT\ccm\dcm -ClassName SMS_DesiredConfiguration -MethodName "TriggerEvaluation" -Arguments $Arguments -ErrorVariable CIMMethodError -ErrorAction Continue -OperationTimeoutSec 30
If ($CIMMethodError)
{
    Return $CIMMethodError
}
Else
{
    Return "Done!"
}