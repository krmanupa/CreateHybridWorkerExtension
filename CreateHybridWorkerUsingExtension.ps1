param(
        [Parameter(Mandatory=$true, Position=0)]
        [string] $SubscriptionId,
        [Parameter(Mandatory=$true, Position=1)]
        [string] $AutomationAccountResourceGroupName,
        [Parameter(Mandatory=$true, Position=2)]
        [string] $AccountName,
        [Parameter(Mandatory=$true, Position=3)]
        [string] $WorkerGroupName,
        [Parameter(Mandatory=$true, Position=4)]
        [string] $VmResourceGroupName,
        [Parameter(Mandatory=$true, Position=5)]
        [string] $VmName,
        [Parameter(Mandatory=$true, Position=6)]
        [string] $OsType,
        [Parameter(Mandatory=$false, Position=7)]
        [string] $SignatureValidationEnabled = $false,
        [Parameter(Mandatory=$false, Position=8)]
        [string] $IsNonAzure = $false        
)

function Login-Account {
    param(
        $SubscriptionId
    )
    try {  
        Write-Verbose "Logging in to Azure..." -verbose
        Select-AzSubscription -SubscriptionId $SubscriptionId
    }
    catch {
        Write-Error -Message $_.Exception
        throw $_.Exception
    }
}

function Get-AccessToken{
    Write-Verbose "Getting access token"

    try{
        $accessToken = Get-AzAccessToken -ResourceUrl "https://management.azure.com/"
        $Token = $accessToken.Token
        return $Token
    }
    catch {
        Write-Error -Message $_.Exception
        throw $_.Exception
    }
}

function Get-VmResourceId {
    param(
        $VmResourceGroupName,
        $VmName
    )
    $vmDetails = Get-AzVM -ResourceGroupName $VmResourceGroupName -Name $vmName
    return $($vmDetails.Id)
}

function Get-HybridWorkerRegUrl {
    param(
        $SubscriptionId,
        $AutomationAccountResourceGroupName,
        $AccountName
    )
    try{
        $access_token = Get-AccessToken
        $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$AutomationAccountResourceGroupName/providers/Microsoft.Automation/automationAccounts/"+$AccountName+"?api-version=2021-06-22"
        $automationaccountInfo = Invoke-GetRestMethod -Uri $uri -Token $access_token -ContentType "application/json"
        return $($automationaccountInfo.properties.automationHybridServiceUrl)
    }
    catch{
        Write-Error "Error getting automation account registration uri : "$_
    }
}

function Invoke-PutRestMethod {
    param (
        $Uri,
        $Body,
        $Token,
        $ContentType
    )
    # Write-Verbose "Draft runbooks" -verbose
    try {
        $Headers = @{}
        $Headers.Add("Authorization", "bearer " + " " + "$($Token)")
        return Invoke-RestMethod -Uri $Uri -Method PUT -ContentType $ContentType -Headers $Headers -Body $Body
    }
    catch {
        Write-Error -Message $_.Exception
    }
}

function Invoke-GetRestMethod {
    param (
        $Uri,
        $Token,
        $ContentType
    )
    try {
        $Headers = @{}
        $Headers.Add("Authorization", "bearer " + " " + "$($Token)")  
        return Invoke-RestMethod -Uri $Uri -Method GET -ContentType $ContentType -Headers $Headers
    }
    catch {
        Write-Error -Message $_.Exception
    }
}

function Create-NewHybridWorkerGroup{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string] $SubscriptionId,
        [Parameter(Mandatory=$true, Position=1)]
        [string] $AutomationAccountResourceGroupName,
        [Parameter(Mandatory=$true, Position=2)]
        [string] $AccountName,
        [Parameter(Mandatory=$true, Position=3)]
        [string] $WorkerGroupName
    )

    Login-Account -SubscriptionId $SubscriptionId
    $access_token = Get-AccessToken 

    $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$AutomationAccountResourceGroupName/providers/Microsoft.Automation/automationAccounts/$AccountName/hybridRunbookWorkerGroups/"+$WorkerGroupName+"?api-version=2021-06-22"
    $body = "{}"

    try{
        Invoke-PutRestMethod -Uri $uri -Body $body -Token $access_token -ContentType "application/json"
    }
    catch{
        Write-Error "Error while creating new worker group : " $_
    }
}

function Add-NewWorkerToWorkerGroup{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string] $SubscriptionId,
        [Parameter(Mandatory=$true, Position=1)]
        [string] $AutomationAccountResourceGroupName,
        [Parameter(Mandatory=$true, Position=2)]
        [string] $AccountName,
        [Parameter(Mandatory=$true, Position=3)]
        [string] $WorkerGroupName,
        [Parameter(Mandatory=$true, Position=4)]
        [string] $VmResourceGroupName,
        [Parameter(Mandatory=$true, Position=5)]
        [string] $VmName
    )

    Write-Output  "Adding a new worker to the Worker Group. VMName: $VmName, VMResourceGroup: $VmResourceGroupName"

   try{

        Login-Account -SubscriptionId $SubscriptionId
        $access_token = Get-AccessToken 

        $uri = Get-VmResourceId -VmResourceGroupName $VmResourceGroupName -VmName $VmName

        
        $body = @"
        { "properties" : { "vmResourceId":  "$vmResourceId"} }
"@

        Invoke-PutRestMethod -Uri $uri -Body $body -Token $access_token -ContentType "application/json"
    }
    catch{
        Write-Error "Error creating new worker : " $_
    }
}

function Enable-VMIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string] $VmResourceGroupName,
        [Parameter(Mandatory=$true, Position=1)]
        [string] $VmName
    )

    try{
        Write-Output "Enabling VM Identity"
        
        Login-Account -SubscriptionId $SubscriptionId

        $vm = Get-AzVM -ResourceGroupName $VmResourceGroupName -Name $vmName
        Update-AzVM -ResourceGroupName $VmResourceGroupName -VM $vm -IdentityType SystemAssigned
    }
    catch{
        Write-Error "Error Enabling system assigned identity on the VM : "$_
    }
}

function Get-VmLocation {
    param(
        $VmResourceGroupName,
        $VmLocation
    )

    $vm = Get-AzVM -ResourceGroupName $VmResourceGroupName -Name $VmName
    return $($vm.Location) 
}

function Enable-HybridWorkerExtension {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string] $SubscriptionId,
        [Parameter(Mandatory=$true, Position=1)]
        [string] $AutomationAccountResourceGroupName,
        [Parameter(Mandatory=$true, Position=2)]
        [string] $AccountName,
        [Parameter(Mandatory=$true, Position=3)]
        [string] $WorkerGroupName,
        [Parameter(Mandatory=$true, Position=4)]
        [string] $VmResourceGroupName,
        [Parameter(Mandatory=$true, Position=5)]
        [string] $VmName,
        [Parameter(Mandatory=$true, Position=6)]
        [string] $OsType,
        [Parameter(Mandatory=$false, Position=7)]
        [string] $SignatureValidationEnabled = $false,
        [Parameter(Mandatory=$false, Position=8)]
        [string] $IsNonAzure = $false       
    )
    Write-Output "Enabling extension on the Hybrid worker"

    Login-Account -SubscriptionId $SubscriptionId
    
    $regisrationUri = Get-HybridWorkerRegUrl
    Write-Output "Registration URL received is : "$regisrationUri

    $settings = @{
        "AutomationAccountURL"  = $regisrationUri;             
        "SignatureValidationEnabled" = $SignatureValidationEnabled; 
    };

    $extensionType = "HybridWorkerForWindows"
    $settings_json = ConvertTo-Json $settings

    $extensionName = "HybridWorkerExtension"
    $publisher = "Microsoft.Azure.Automation.HybridWorker"

    if($OsType -eq "Linux"){
        $extensionType = "HybridWorkerForLinux"
    }

    $VmLocation = Get-VmLocation -VmResourceGroupName $VmResourceGroupName -VmName $VmName

    Write-Output "Settings provided are : $settings_json"
    Write-Output "Extension Type : $extensionType"
    try {

        if($IsNonAzure){
            New-AzConnectedMachineExtension -ResourceGroupName $VmResourceGroupName -Location VmLocation  -MachineName $VmName -Name $extensionName -Publisher $publisher -ExtensionType $extensionType -TypeHandlerVersion 0.1 -Settings $settings 
        }
        else{
            Set-AzVMExtension -ResourceGroupName $VmResourceGroupName -Location $VmLocation  -VMName $VmName -Name $extensionName -Publisher $publisher -ExtensionType $extensionType -TypeHandlerVersion 0.1 -Settings $settings 
        }

    }
    catch {
        Write-Error "HWGV2 Creation :: Error enabling Hybrid worker extension - $_"
    }

    Get-AzAutomationHybridWorkerGroup -AutomationAccountName $AccountName -ResourceGroupName $AutomationAccountResourceGroupName -Name $WorkerGroupName
    Write-Output "Creation of HWG V2 Successful"
}

function Enable-HybridWorkerExtensionE2E {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string] $SubscriptionId,
        [Parameter(Mandatory=$true, Position=1)]
        [string] $AutomationAccountResourceGroupName,
        [Parameter(Mandatory=$true, Position=2)]
        [string] $AccountName,
        [Parameter(Mandatory=$true, Position=3)]
        [string] $WorkerGroupName,
        [Parameter(Mandatory=$true, Position=4)]
        [string] $VmResourceGroupName,
        [Parameter(Mandatory=$true, Position=5)]
        [string] $VmName,
        [Parameter(Mandatory=$true, Position=6)]
        [string] $OsType,
        [Parameter(Mandatory=$false, Position=7)]
        [string] $SignatureValidationEnabled = $false,
        [Parameter(Mandatory=$false, Position=8)]
        [string] $IsNonAzure = $false        
    )

    Write-Output "Creating New Hybrid Worker Group. WorkerGroupName : $WorkerGroupName, AutomationAccount : $AccountName"
    Create-NewHybridWorkerGroup -SubscriptionId $SubscriptionId -AutomationAccountResourceGroupName $AutomationAccountResourceGroupName -AccountName $AccountName -WorkerGroupName $WorkerGroupName

    Write-Output "Adding a new worker to the Worker Group. VMName: $VmName, VMResourceGroup: $VmResourceGroupName"
    Add-NewWorkerToWorkerGroup -SubscriptionId $SubscriptionId -AutomationAccountResourceGroupName $AutomationAccountResourceGroupName -AccountName $AccountName -WorkerGroupName $WorkerGroupName -VmResourceGroup $VmResourceGroupName -VmName $VmName

    Write-Output "Enabling Identity for the VM. VMName: $VmName, VMResourceGroup: $VmResourceGroupName"
    Enable-Identity -VmResourceGroupName $VmResourceGroupName -VmName $VmName

    Write-Output "Enabling Hybrid Worker Extension on VMType: $OsType"
    Enable-HybridWorkerExtension -SubscriptionId $SubscriptionId -AutomationAccountResourceGroupName $AutomationAccountResourceGroupName -AccountName $AccountName -WorkerGroupName $WorkerGroupName -VmResourceGroup $VmResourceGroupName -VmName $VmName -OsType $OsType -SignatureValidationEnabled $SignatureValidationEnabled -IsNonAzure $IsNonAzure
}

Enable-HybridWorkerExtensionE2E -SubscriptionId $SubscriptionId -AutomationAccountResourceGroupName $AutomationAccountResourceGroupName -AccountName $AccountName -WorkerGroupName $WorkerGroupName -VmResourceGroup $VmResourceGroupName -VmName $VmName -OsType $OsType -SignatureValidationEnabled $SignatureValidationEnabled -IsNonAzure $IsNonAzure

