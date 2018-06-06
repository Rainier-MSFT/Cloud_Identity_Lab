############# GLOBALS  ###################################################################################

$ResourceGroupOwner = "Rainier"  # Name of resource group owner - Must be unique
$labPrefix = "Wacketywack"  # Must be unique and storage account with same name cannot already exist
$DCName = "DC-01"   # Must be unique for region if want to RDP using public DNS, instead of IP (E.g. <hostname>.uksouth.cloudapp.azure.com)
$ADForestName = "wacketywack.local"
$VNetIPBlock = "192.168.0.0/24" # Avoid overlap between VNets in different RGs, by using diffrent 3rd octet if poss
$LANSubnetIPBlock = "192.168.0.0/25" # Provides 108 hosts, leaving plenty for GW SNet

## - Host names will need to contain role, so that script logic can apply function specific additions. E.g. MFA server will only be provisioned with MFAServer.exe package if "mfa" is in hostname. Same for RDS, etc. 
## - Some resources such as automation accounts are identified by name and can only exist once, Azure wide. Therefore Lab prefix must be different for every new enviroment being spun-up.
## - Script assumes that only one VNET exists for the enviroment, per RG
## - Note that if testing, DNS records for public IP's must be unique.E.g. If you have a VM defined with a hostname of "mfa-01" then a corresponding public DNS fqdn record will be created as "mfa-01.westeurope.cloudapp.azure.com", and the choosen location will be used to define the suffix. So you may find a dup record prevents the new VM from being instantiated.

#############  Use for debugging  #######################################################################
# Set-PSDebug -Trace 2 -step # Set-PSDebug -Trace 0
# $DebugPreference="Continue"

#########################################################################################################

[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
$host.ui.RawUI.WindowTitle = "Cloud Identity Lab"

CLS
New-Item -path "$env:APPDATA\Windows Azure Powershell" -type directory -ErrorAction SilentlyContinue | Out-Null
Set-Content -path "$env:APPDATA\Windows Azure Powershell\AzureDataCollectionProfile.json" -value '{"enableAzureDataCollection":false}'

## Check if elevated
#Write-Host "`n[MAIN]:" -ForegroundColor Yellow -NoNewline
#Write-Host " - Check if session is elevated. " -NoNewline
#if (-not ([bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544"))) {
#    Write-Host "Not running as admin so exiting...`n" -ForegroundColor DarkGray
#    exit
#} else {
#    Write-Host "Done" -ForegroundColor Green
#}

#AuthN to Azure
#======================================
Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
Write-Host " - Login with a Global Administrator account...." -NoNewline
if ([string]::IsNullOrEmpty($(Get-AzureRmContext).Account)) {Login-AzureRmAccount}
Write-Host

#Subsciption picker
Try
{       
    Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
    Write-Host " - Querying account for subscriptions...." -NoNewline
	$Subs = Get-AzureRMSubscription -WA SilentlyContinue
 
    [void][reflection.assembly]::Load('System.Windows.Forms, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')
    $formShowmenu = New-Object 'System.Windows.Forms.Form'
    $combobox1 = New-Object 'System.Windows.Forms.ComboBox'
    $combobox1_SelectedIndexChanged = { 
    $script:var = $combobox1.SelectedItem
    $formShowmenu.Close()
    }
 
    $formShowmenu.Controls.Add($combobox1)
    $formShowmenu.TopMost = $true
    $formShowmenu.FormBorderStyle = 'Fixed3D'
    $formShowmenu.MaximizeBox = $false
    $formShowmenu.StartPosition = "CenterScreen"
    $formShowmenu.ControlBox = $false
    $formShowmenu.Text = ' Please select your subscription...'
    $formShowmenu.ClientSize = '490, 52'
  
    #Array subscriptions
    [void]$combobox1.Items.AddRange($Subs.Name)
 
    $combobox1.Location = '26, 12'
    $combobox1.Size = '440, 22'
    $combobox1.Font = '6, 10'
    $combobox1.DropDownStyle = 'DropDownList'
    $combobox1.add_SelectedIndexChanged($combobox1_SelectedIndexChanged)
    Write-Host "Done" -ForegroundColor Green
    $formShowmenu.ShowDialog() | out-null

    Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
    Write-Host " - Mapping session to target subscription...." -NoNewline
    Select-AzureRMSubscription –SubscriptionName $var | Out-Null
    Set-AzureRmContext -SubscriptionName $var | Out-Null
    Write-Host " [" -NoNewline
    Write-Host "$var" -NoNewline -ForegroundColor Green
    Write-Host "]" 
}
    Catch{
    Write-Host "`nNo subscriptions found. Exiting`n" -ForegroundColor Red
    Exit
}
$formShowmenu.Dispose()

Function New-AzureLabWindowsServerVM {
    param(
        [Parameter(Mandatory=$true)][string]$VMName,
        [Parameter(Mandatory=$true)][string]$Location,
        [Parameter(Mandatory=$true)][string]$ResourceGroupName,
        [Parameter(Mandatory=$true)][string]$VNETId,
        [Parameter(Mandatory=$true)][string]$VNETSGId,
        [Parameter(Mandatory=$true)][string]$VMSize,
        [Parameter(Mandatory=$true)][string]$PrivateIP,
        [Parameter(Mandatory=$true)][PSCredential]$LocalAdmin,
        [Parameter(Mandatory=$true)][string]$SKU,
        [Parameter(Mandatory=$true)][string]$StorageBlobURI,
        [switch]$JoinDomain,
        [string]$DomainName,
        [PSCredential]$DomainAdmin
    )

		Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
        Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
        Write-Host " - Querying VM status...." -NoNewline
	    if(-Not (Find-AzureRmResource -ResourceType "Microsoft.Compute/virtualMachines" -ResourceGroupNameEquals $ResourceGroupName -ResourceNameContains $VMName)) {
            Write-Host "Done" -ForegroundColor Green

            #Create Public IP Address
            #========================
            Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
            Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
            Write-Host " - Creating Public IP...." -NoNewline
			if(-Not (Find-AzureRmResource -ResourceType "Microsoft.Network/publicIPAddresses" -ResourceGroupNameEquals $ResourceGroupName -ResourceNameContains "$($VMName)-public-ip")) {
				try { 
                     $PIP = New-AzureRmPublicIpAddress -WA 0 `
					-Name "$($VMName)-public-ip" `
					-ResourceGroupName $ResourceGroupName `
					-Location $Location `
					-DomainNameLabel ($VMName + "-" + $labPrefix + "-rdp").ToLower() `
					-AllocationMethod Dynamic
                    $PIP = $PIP.id

				Write-Host "Done" -ForegroundColor Green }
                catch {
                    Write-Host "Unable to create interface. Exiting" -ForegroundColor DarkGray
                    Exit
                } }
            else {
				Write-Host "Interface already exists. Moving on" -ForegroundColor DarkGray
                $PIP = (Get-AzureRmPublicIpAddress -ResourceGroupName $ResourceGroupName -Name "$($VMName)-public-ip").Id
			}

            #Create NIC Interface to be attached to VM
            #=========================================
            Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
            Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
            Write-Host " - Creating NIC...." -NoNewline
			if(-Not (Find-AzureRmResource -ResourceType "Microsoft.Network/networkinterfaces" -ResourceGroupNameEquals $ResourceGroupName -ResourceNameContains "$($VMName)-nic")) {
                try {
				     $NIC = New-AzureRmNetworkInterface -WA 0 `
					-Name "$($VMName)-nic" `
					-ResourceGroupName $ResourceGroupName `
					-Location $Location `
					-SubnetId $VNETSubID `
					-PrivateIpAddress $PrivateIP `
					-PublicIpAddressId $PIP `
					-NetworkSecurityGroupId $VNETSGId
				Write-Host "Done" -ForegroundColor Green }
                catch {
                    Write-Host "Unable to create interface. Exiting" -ForegroundColor DarkGray
                    Exit } 
            }
            else {
				Write-Host "Interface already exists. Moving on" -ForegroundColor DarkGray
				$NIC = Get-AzureRmNetworkInterface -ResourceGroupName $ResourceGroupName -Name "$($VMName)-nic"
			}

            #Construct VM Configuration Object
            #=================================
            Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
            Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
            Write-Host " - Creating VM Configuration...." -NoNewline
            $OSDISKURI = $StorageBlobURI + "vhds/" + $VMName + "sys.vhd"
            $VM = New-AzureRmVMConfig -VMName $VMName -VMSize $VMSize -WA 0
            $VM = Set-AzureRmVMOperatingSystem -VM $VM -Windows -ComputerName $VMName -Credential $LocalAdmin -ProvisionVMAgent -EnableAutoUpdate -WinRMHttp -WA 0
            $VM = Set-AzureRmVMSourceImage -VM $VM -PublisherName MicrosoftWindowsServer -Offer WindowsServer -Skus $SKU -Version "latest" -WA 0
            $VM = Add-AzureRmVMNetworkInterface -VM $VM -Id $NIC.Id -WA 0
            $VM = Set-AzureRmVMOSDisk -VM $VM -Name "$($VMName)sys" -vhd $OSDISKURI -CreateOption fromImage -WA 0
            Write-Host "Done" -ForegroundColor Green
         
            #Create VM
            #=========
            Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
            Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
            Write-Host " - Provision VM....`n" -NoNewline
            New-AzureRmVM -ResourceGroupName $ResourceGroupName -Location $Location -VM $VM -WA 0

            #Join Domain if requested
            #========================
            if ($JoinDomain){
                Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
                Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                Write-Host " - Joining to $($domainName) domain....`n" -NoNewline
                Set-AzureRMVMExtension -WA 0 `
                -VMName $VMName `
                -ResourceGroupName $ResourceGroupName `
                -Name "JoinAD" `
                -ExtensionType "JsonADDomainExtension" `
                -Publisher "Microsoft.Compute" `
                -TypeHandlerVersion "1.0" `
                -Location $Location `
                -Settings @{ "Name" = $domainName; "OUPath" = ""; "User" = "$($DomainAdmin.Username)@$domainName"; "Restart" = "true"; "Options" = 3} -ProtectedSettings @{"Password" = "$($DomainAdmin.GetNetworkCredential().Password)"} 
            }

                    #Create BLOB Storage Container to host scripts
                    #=============================================
                    Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
                    Write-Host " - Creating scripts container...." -NoNewline
                    $VMInfo = Get-AzureRmVM -ResourceGroupName $ResourceGroupName -Name $DCName -WA 0
                    $Key = (Get-AzureRmStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $STORAGE.StorageAccountName -WA 0).Value[0]
                    $StorageContext = New-AzureStorageContext -StorageAccountName $STORAGE.StorageAccountName -StorageAccountKey $Key
                    if(Get-AzureStorageContainer -Context $StorageContext | ? {$_.name -eq "scripts"}) {
                        Write-Host "Already exists. Moving on" -ForegroundColor DarkGray
                    }   else {
                        "`n"
                        New-AzureStorageContainer -Name "scripts" -Context $StorageContext -WA 0
                    }
                
                if ($VMName -eq $DCName) {
                    
                    #Generate random PW for DS restore
                    #=================================
                    Function New-RandomPassword{
	                    param(
		                    [Parameter(
			                    Mandatory=$true,
			                    Position=0
		                    )]
		                    [int]$Length=8
	                    )
	                    $password = ""
	                    $arrChars = @(35..38+40..47+58..64+123..126),@(48..57),@(97..122),@(65..90)
	                    #Construct Password
	                    #==================
	                    1..($Length-4) | % {$password+="$([char]($arrChars[(Get-Random (0..3))] | Get-Random))"}
	                    0..3 | % {$password = $password.Insert((Get-Random (0..($password.Length-1))),"$([char]($arrChars[$_] | Get-Random))")}
                        return $password
                    }
                    
                    #Forest provisioning script
                    #==========================
                    Write-Host "[CREATEINFRA]:" -ForegroundColor Yellow -NoNewline
                    Write-Host " - Provisioning AD Forest...."
                    $DCScript = 
@'

$logDirectory = "C:\logs"
New-Item -ItemType Directory -Path $logDirectory -Force
Start-Transcript -Path "$logDirectory\ADDS.log"

Import-Module servermanager
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

$DSRestorePW = ConvertTo-SecureString -String '#password#' -AsPlainText -Force

Import-Module activedirectory
$ForestParams = @{
CreateDnsDelegation = $false
DomainName = "#domain#"
NoRebootOnCompletion = $true
SafeModeAdministratorPassword = $DSRestorePW
Force = $true
Verbose = $true
}

Install-ADDSForest @ForestParams

Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

$AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
$UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0

Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 00000000

Install-WindowsFeature AD-Certificate,ADCS-Cert-Authority,ADCS-Web-Enrollment -IncludeManagementTools
Install-AdcsCertificationAuthority -CAType EnterpriseRootCa -Force

Stop-Transcript

#Schedule Reboot
Start-Sleep -Seconds 60
Restart-Computer -ComputerName . -Force 
'@ 

                    
                    #Upload script with replaced variables
                    #=====================================
                    $DCScript = $DCScript -replace '#domain#', $ADForestName
                    $DSRestorePW = New-RandomPassword -Length 12
                    $DCScript = $DCScript -replace '#password#', $DSRestorePW
                    $DCScript | Out-File $env:TEMP\New-Forest.ps1 -Force
                     
                    #Push script
                    #============
                    Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Uploading automation script to container....`n" -NoNewline
                    Set-AzureStorageBlobContent -Container "scripts" -File $env:TEMP\New-Forest.ps1 -Blob "New-Forest.ps1" -Context $StorageContext -force -WA 0
                                
                    #Add custom script to DC
                    #=======================
                    Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Adding custom extension to DC...." -NoNewline
                    $Ext = Set-AzureRmVMCustomScriptExtension -WA 0 `
                           -ResourceGroupName $ResourceGroupName `
                           -VMName $DCName `
                           -Name "$($labPrefix)-Forest" `
                           -Location $VMInfo.Location `
                           -StorageAccountName $STORAGE.StorageAccountName `
                           -StorageAccountKey $Key `
                           -FileName "New-Forest.ps1" `
                           -ContainerName "scripts" #-Verbose
                    Write-Host "Done" -ForegroundColor Green }

            elseif ($VMName -like "*adfs*") {
                    
                    #Create Roles and Features script
                    #================================
                    Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Provisioning VM with roles and features....`n"
                    $RolesScript = 
@'

$logDirectory = "C:\logs"
New-Item -ItemType Directory -Path $logDirectory -Force
Start-Transcript -Path "$logDirectory\Roles.log"

Import-Module servermanager
Install-WindowsFeature -Name ADFS-Federation -IncludeManagementTools

Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

$AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
$UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0

Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 00000000

Stop-Transcript

#Schedule Reboot
Start-Sleep -Seconds 60
Restart-Computer -ComputerName . -Force 
'@ 

                    #Push script
                    #============
                    $RolesScript | Out-File $env:TEMP\ADFS-Role.ps1 -Force
                    Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
                    Write-Host " - Uploading automation script to container....`n" -NoNewline
                    Set-AzureStorageBlobContent -Container "scripts" -File $env:TEMP\ADFS-Role.ps1 -Blob "ADFS-Role.ps1" -Context $StorageContext -force -WA 0

                    #Add custom script to VM
                    #=======================
                    Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Adding custom extension to VM...." -NoNewline
                    $Ext = Set-AzureRmVMCustomScriptExtension -WA 0 `
                           -ResourceGroupName $ResourceGroupName `
                           -VMName $VMName `
                           -Name "$($labPrefix)-Roles" `
                           -Location $VMInfo.Location `
                           -StorageAccountName $STORAGE.StorageAccountName `
                           -StorageAccountKey $Key `
                           -FileName "ADFS-Role.ps1" `
                           -ContainerName "scripts" #-Verbose
                    Write-Host "Done" -ForegroundColor Green 
                    }
                    
          elseif ($VMName -like "*wap*") {

                    #Create Roles and Features script
                    #================================
                    Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Provisioning VM with roles and features....`n"
                    $RolesScript = 
@'

$logDirectory = "C:\logs"
New-Item -ItemType Directory -Path $logDirectory -Force
Start-Transcript -Path "$logDirectory\Roles.log"

Import-Module servermanager
Install-WindowsFeature -name Web-Application-Proxy -IncludeManagementTools

Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

$AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
$UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0

Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 00000000

Stop-Transcript

#Schedule Reboot
Start-Sleep -Seconds 60
Restart-Computer -ComputerName . -Force 
'@ 

                    #Push script
                    #============
                    $RolesScript | Out-File $env:TEMP\WAP-Role.ps1 -Force
                    Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
                    Write-Host " - Uploading script to container....`n" -NoNewline
                    Set-AzureStorageBlobContent -Container "scripts" -File $env:TEMP\WAP-Role.ps1 -Blob "WAP-Role.ps1" -Context $StorageContext -force -WA 0
                    Write-Host "Done" -Foregroundcolor Green

                    #Add custom script to VM
                    #=======================
                    Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
                    Write-Host " - Adding custom extension to VM...." -NoNewline
                    $Ext = Set-AzureRmVMCustomScriptExtension -WA 0 `
                           -ResourceGroupName $ResourceGroupName `
                           -VMName $VMName `
                           -Name "$($labPrefix)-Roles" `
                           -Location $VMInfo.Location `
                           -StorageAccountName $STORAGE.StorageAccountName `
                           -StorageAccountKey $Key `
                           -FileName "WAP-Role.ps1" `
                           -ContainerName "scripts" #-Verbose
                    Write-Host "Done" -ForegroundColor Green 
                    }
                    
                    elseif ($VMName -like "*mfa*") {
                    
                    #Create Roles and Features script
                    #================================
                    Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Provisioning VM with roles and features....`n"
                    $RolesScript = 
@'

$logDirectory = "C:\logs"
New-Item -ItemType Directory -Path $logDirectory -Force
Start-Transcript -Path "$logDirectory\Roles.log"

Import-Module servermanager
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
add-windowsfeature web-server -includeallsubfeature

Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

$AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
$UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0

Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 00000000

Import-Module BitsTransfer
Start-BitsTransfer -Source "https://download.microsoft.com/download/9/E/0/9E006C56-BFDE-4802-8683-201A35C3ED68/MultiFactorAuthenticationServerSetup.exe" -Destination "C:\Users\Public\Desktop\MultiFactorAuthenticationServerSetup.exe"

$Shell = New-Object -ComObject ("WScript.Shell")
$ShortCut = $Shell.CreateShortcut($env:USERPROFILE + "\Desktop\MFAServer Blade.lnk")
$ShortCut.TargetPath = "C:\Program Files (x86)\Internet Explorer\iexplore.exe"
$ShortCut.Arguments = "https://portal.azure.com/#blade/Microsoft_AAD_IAM/MultifactorAuthenticationMenuBlade/ServerSettings/fromProviders//hasMFALicense/true"
$ShortCut.WorkingDirectory = "C:\Program Files (x86)\Internet Explorer";
$ShortCut.WindowStyle = 1;
$ShortCut.IconLocation = "iexplore.exe, 0";
$ShortCut.Save()

Stop-Transcript

#Schedule Reboot
Start-Sleep -Seconds 60
Restart-Computer -ComputerName . -Force 
'@ 

                    #Push script
                    #============
                    $RolesScript | Out-File $env:TEMP\MFA-Role.ps1 -Force
                    Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
                    Write-Host " - Uploading script to container....`n" -NoNewline
                    Set-AzureStorageBlobContent -Container "scripts" -File $env:TEMP\MFA-Role.ps1 -Blob "MFA-Role.ps1" -Context $StorageContext -force -WA 0
                    Write-Host "Done" -Foregroundcolor Green

                    #Add custom script to VM
                    #=======================
                    Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
                    Write-Host " - Adding custom extension to VM...." -NoNewline
                    $Ext = Set-AzureRmVMCustomScriptExtension -WA 0 `
                           -ResourceGroupName $ResourceGroupName `
                           -VMName $VMName `
                           -Name "$($labPrefix)-Roles" `
                           -Location $VMInfo.Location `
                           -StorageAccountName $STORAGE.StorageAccountName `
                           -StorageAccountKey $Key `
                           -FileName "MFA-Role.ps1" `
                           -ContainerName "scripts" #-Verbose
                    Write-Host "Done" -ForegroundColor Green
                    }
                    elseif ($VMName -like "*tmg*") {
                    
                    #Create Roles and Features script
                    #================================
                    Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Provisioning VM with roles and features....`n"
                    $RolesScript = 
@'

$logDirectory = "C:\logs"
New-Item -ItemType Directory -Path $logDirectory -Force
Start-Transcript -Path "$logDirectory\Roles.log"

Import-Module servermanager
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
add-windowsfeature web-server -includeallsubfeature

Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

$AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
$UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0

Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 00000000

Import-Module BitsTransfer
Start-BitsTransfer -Source "https://download.microsoft.com/download/7/4/5/745F8FD4-C3B3-4E97-8702-8359CB4DF947/TMG_ENU_SE_EVAL_AMD64.exe" -Destination "C:\Users\Public\Desktop\TMG_ENU_SE_EVAL_AMD64.exe"

$Shell = New-Object -ComObject ("WScript.Shell")
$ShortCut = $Shell.CreateShortcut($env:USERPROFILE + "\Desktop\MFAServer Blade.lnk")
$ShortCut.TargetPath = "C:\Program Files (x86)\Internet Explorer\iexplore.exe"
$ShortCut.Arguments = "https://portal.azure.com/#blade/Microsoft_AAD_IAM/MultifactorAuthenticationMenuBlade/ServerSettings/fromProviders//hasMFALicense/true"
$ShortCut.WorkingDirectory = "C:\Program Files (x86)\Internet Explorer";
$ShortCut.WindowStyle = 1;
$ShortCut.IconLocation = "iexplore.exe, 0";
$ShortCut.Save()

Stop-Transcript

#Schedule Reboot
Start-Sleep -Seconds 60
Restart-Computer -ComputerName . -Force 
'@ 

                    #Push script
                    #============
                    $RolesScript | Out-File $env:TEMP\TMG-Role.ps1 -Force
                    Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
                    Write-Host " - Uploading script to container....`n" -NoNewline
                    Set-AzureStorageBlobContent -Container "scripts" -File $env:TEMP\TMG-Role.ps1 -Blob "TMG-Role.ps1" -Context $StorageContext -force -WA 0
                    Write-Host "Done" -Foregroundcolor Green

                    #Add custom script to VM
                    #=======================
                    Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
                    Write-Host " - Adding custom extension to VM...." -NoNewline
                    $Ext = Set-AzureRmVMCustomScriptExtension -WA 0 `
                           -ResourceGroupName $ResourceGroupName `
                           -VMName $VMName `
                           -Name "$($labPrefix)-Roles" `
                           -Location $VMInfo.Location `
                           -StorageAccountName $STORAGE.StorageAccountName `
                           -StorageAccountKey $Key `
                           -FileName "TMG-Role.ps1" `
                           -ContainerName "scripts" #-Verbose
                    Write-Host "Done" -ForegroundColor Green
                    }
                    elseif ($VMName -like "*rds*") {
                    #Create Roles and Features script
                    #================================
                    Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Provisioning VM with roles and features....`n"
                    $RolesScript = 
@'

$logDirectory = "C:\logs"
New-Item -ItemType Directory -Path $logDirectory -Force
Start-Transcript -Path "$logDirectory\Roles.log"

Import-Module servermanager
Add-WindowsFeature RDS-RD-Server,RDS-Licensing,RDS-Licensing-UI,RSAT-RDS-Licensing-Diagnosis-UI,RDS-Session-Host,RDS-Gateway,RDS-Web-Access,RDS-Connection-Broker

$AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
$UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0

Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 00000000d:

Stop-Transcript

#Schedule Reboot
Start-Sleep -Seconds 60
Restart-Computer -ComputerName . -Force 
'@ 

                    #Push script
                    #============
                    $RolesScript | Out-File $env:TEMP\RDS-Role.ps1 -Force
                    Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
                    Write-Host " - Uploading script to container....`n" -NoNewline
                    Set-AzureStorageBlobContent -Container "scripts" -File $env:TEMP\RDS-Role.ps1 -Blob "RDS-Role.ps1" -Context $StorageContext -force -WA 0
                    Write-Host "Done" -Foregroundcolor Green

                    #Add custom script to VM
                    #=======================
                    Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
                    Write-Host " - Adding custom extension to VM...." -NoNewline
                    $Ext = Set-AzureRmVMCustomScriptExtension -WA 0 `
                           -ResourceGroupName $ResourceGroupName `
                           -VMName $VMName `
                           -Name "$($labPrefix)-Roles" `
                           -Location $VMInfo.Location `
                           -StorageAccountName $STORAGE.StorageAccountName `
                           -StorageAccountKey $Key `
                           -FileName "RDS-Role.ps1" `
                           -ContainerName "scripts" #-Verbose
                    Write-Host "Done" -ForegroundColor Green
                    }



}  else {
         Write-Host "$VMName already exists. Moving on" -ForegroundColor DarkGray
        }
}

#$arrVMNames = @()
#$labPrefix = $labPrefix.ToLower() #MUST be lowercase

IF([string]::IsNullOrEmpty($ForestCreds.UserName)) {
    $ForestCreds = Get-Credential -Message "Enter credentials to be used as the $($ADForestName) domain administrator account. Note - The username cannot contain the string 'Administrator and the password must meet standard complexity requirements"
    $Credentials = Get-Credential -Message "Enter credentials to be used as the VM's local admin account. Note - The username cannot contain the string 'Administrator and the password must meet standard complexity requirements"
}

#Geo picker
#=====================
Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
Write-Host " - Querying for existing resource group...." -NoNewline
$ResourceGroupName = $ResourceGroupOwner + "-" + $labPrefix + "-RG"
Get-AzureRmResourceGroup -Name $ResourceGroupName -ev notPresent -ea 0 | Out-Null
if ($notPresent) { 
    Write-Host "Done" -ForegroundColor Green
    Try
    {       
        Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
        Write-Host " - Querying account for locations that support all required resource types...." -NoNewline
	    $Geos = Get-AzureRmLocation | ? {$_.Providers -like '*Automation*' }
        [void][reflection.assembly]::Load('System.Windows.Forms, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')
        $formShowmenu = New-Object 'System.Windows.Forms.Form'
        $combobox1 = New-Object 'System.Windows.Forms.ComboBox'
        $combobox1_SelectedIndexChanged = { 
        $script:var1 = $combobox1.SelectedItem
        $formShowmenu.Close()
        }
        $formShowmenu.Controls.Add($combobox1)
        $formShowmenu.TopMost = $true
        $formShowmenu.FormBorderStyle = 'Fixed3D'
        $formShowmenu.MaximizeBox = $false
        $formShowmenu.StartPosition = "CenterScreen"
        $formShowmenu.ControlBox = $false
        $formShowmenu.Text = ' Please select your prefered deployment geo...'
        $formShowmenu.ClientSize = '490, 52'
        #Array subscriptions
        [void]$combobox1.Items.AddRange($Geos.Location)
        $combobox1.Location = '26, 12'
        $combobox1.Size = '440, 22'
        $combobox1.Font = '6, 10'
        $combobox1.DropDownStyle = 'DropDownList'
        $combobox1.add_SelectedIndexChanged($combobox1_SelectedIndexChanged)
        Write-Host "Done" -ForegroundColor Green
        $formShowmenu.ShowDialog() | out-null
        $Location = $var1

        Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
        Write-Host " - Targeted deployment geo.... [" -NoNewline
        Write-Host "$var1" -NoNewline -ForegroundColor Green
        Write-Host "]"
    }
        Catch{
        Write-Host "`nNo geo locations found. Exiting`n" -ForegroundColor Red
        exit
    }
    $formShowmenu.Dispose()
    $RG = New-AzureRmResourceGroup -Name $ResourceGroupName -Location $Location -WA 0
}
else {
    Write-Host "Resource Group already exists. Moving on" -ForegroundColor DarkGray
    $RG = get-AzureRmResourceGroup -Name $ResourceGroupName -WA 0
    $Location = $RG.Location
}

#Create Automation Account to hold runbooks/dsc configs
#======================================================
Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
Write-Host " - Creating Automation Account...." -NoNewline
if(-not (Find-AzureRmResource -ResourceGroupNameContains $ResourceGroupName -ResourceType "Microsoft.Automation/automationAccounts" -ResourceNameContains "$($labPrefix)-aa" -WA 0)) {
    Try {    
        $AUTOACC = New-AzureRmAutomationAccount -ResourceGroupName $ResourceGroupName -Name "$($labPrefix)-aa" -Location $Location -WA 0
        Write-Host "Done" -ForegroundColor Green
  } catch {
        $ErrorMessage = $_.Exception.Message
        $FailedItem = $_.Exception.ItemName
        Write-Host "Unable to create automation account" -ForegroundColor DarkGray
        Break  
        }
}
else {
    $AUTOACC = get-AzureRmAutomationAccount -WA 0
    Write-Host "Automation account already exists. Moving on" -ForegroundColor DarkGray
}

#Create Int VNET Rule to allow RDP to all VMs
#============================================
Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
Write-Host " - Generating Internal VNET Ruleset: " -NoNewline
Write-Host "RDP to VMs...." -ForegroundColor Cyan -NoNewline
$arrVNETRulesInt = @()
$INTVNETSR = New-AzureRmNetworkSecurityRuleConfig -WA 0 `
    -Name "allow-rdp-access" `
    -Description "Allow RDP Access to VMs" `
    -Protocol Tcp -SourcePortRange * `
    -DestinationPortRange 3389 `
    -SourceAddressPrefix * `
    -DestinationAddressPrefix * `
    -Access Allow -Priority 100 `
    -Direction Inbound
$arrVNETRulesInt += $INTVNETSR
Write-Host "Done" -ForegroundColor Green

#Create Int VNET Rule to allow 443 to WAP
#========================================
Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
Write-Host " - Generating Internal VNET Ruleset: " -NoNewline
Write-Host "443 to WAP...." -ForegroundColor Cyan -NoNewline
$INTVNETSR1 = New-AzureRmNetworkSecurityRuleConfig -WA 0 `
    -Name "allow-https-access" `
    -Description "Allow 443 to WAP" `
    -Protocol Tcp -SourcePortRange * `
    -DestinationPortRange 443 `
    -SourceAddressPrefix * `
    -DestinationAddressPrefix * `
    -Access Allow -Priority 101 `
    -Direction Inbound
$arrVNETRulesInt += $INTVNETSR1
Write-Host "Done" -ForegroundColor Green

#Create Int VNET Rule to allow 49443 to WAP
#========================================
Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
Write-Host " - Generating Internal VNET Ruleset: " -NoNewline
Write-Host "49443 to WAP.... " -ForegroundColor Cyan -NoNewline
$INTVNETSR2 = New-AzureRmNetworkSecurityRuleConfig -WA 0 `
    -Name "allow-clientcertauth-access" `
    -Description "Allow 49443 to WAP" `
    -Protocol Tcp -SourcePortRange * `
    -DestinationPortRange 49443 `
    -SourceAddressPrefix * `
    -DestinationAddressPrefix * `
    -Access Allow -Priority 102 `
    -Direction Inbound
$arrVNETRulesInt += $INTVNETSR2
Write-Host "Done" -ForegroundColor Green

#Create VNET Security Group
#==========================
Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
Write-Host " - Creating Network Security Group (NSG) & Rules...." -NoNewline
if(-not (Find-AzureRmResource -ResourceType "Microsoft.Network/networkSecurityGroups" -ResourceNameContains "$($labPrefix)-Int-NSG" -ResourceGroupNameContains $ResourceGroupName -ErrorAction SilentlyContinue -WA 0)) {
	$INTVNETSG = New-AzureRmNetworkSecurityGroup -WA 0 `
	-Name "$($labPrefix)-Int-NSG" `
	-ResourceGroupName $ResourceGroupName `
	-Location $Location `
	-SecurityRules $arrVNETRulesInt `
	-Force
	Write-Host "Done" -ForegroundColor Green
}
else {
	Write-Host "NSG already exists. Moving on" -ForegroundColor DarkGray
    $INTVNETSG = Get-AzureRmNetworkSecurityGroup -ResourceGroupName $ResourceGroupName -Name "$($labPrefix)-Int-NSG"
}


#Create Int Subnet
#=================
Write-Host "[CREATEINFRA]:" -ForegroundColor Yellow -NoNewline
Write-Host " - Creating VNET Subnet...." -NoNewline
	$INTVNETSUBNET = New-AzureRmVirtualNetworkSubnetConfig -WA 0 `
	-NetworkSecurityGroup $INTVNETSG `
	-Name "$($labPrefix)-SubNet" `
	-AddressPrefix $LANSubnetIPBlock
    $LanSubnetIPBlock,$LANSubnetCIDR = $LanSubnetIPBlock.Split("/")
	Write-Host "Done" -ForegroundColor Green


#Create VNET 
#===========
Write-Host "[CREATEINFRA]:" -ForegroundColor Yellow -NoNewline
Write-Host " - Creating VNET...." -NoNewline
if (-not (Find-AzureRmResource -ResourceGroupNameContains $ResourceGroupName -ResourceType "Microsoft.Network/virtualNetworks" -ResourceNameContains "$($labPrefix)-VNET" -WA 0)) {
        $VNET = New-AzureRmVirtualNetwork -WA 0 `
			-Name "$($labPrefix)-VNET" `
			-ResourceGroupName $ResourceGroupName `
			-Location $Location `
			-AddressPrefix $VNetIPBlock `
			-DnsServer @($($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.50"), '8.8.4.4') `
			-Subnet $INTVNETSUBNET
        
        $VNETSubID = $VNET.Subnets[0].Id
        $VNetIPBlock = $VNetIPBlock.Split("/") 
		Write-Host "Done" -ForegroundColor Green		
}
else {
		Write-Host "VNET already exists. Moving on..." -ForegroundColor DarkGray
        $VNET = Get-AzureRmVirtualNetwork -Name "$($labPrefix)-VNET"  -ResourceGroupName $ResourceGroupName -WA 0
		$VNETSubID = $VNET.Subnets[0].Id 
}

#Create Shared Storage Account # Name used MUST be unique!
#=========================================================
Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
Write-Host " - Creating Shared Storage...." -NoNewline
if (-not (Find-AzureRmResource -ResourceGroupNameContains $ResourceGroupName -ResourceType "Microsoft.Storage/storageAccounts" -ResourceNameContains "$($labPrefix)storage" -WA 0)) {
	try {
        $STORAGE = New-AzureRmStorageAccount -WA 0 `
		        -ResourceGroupName $ResourceGroupName `
		        -Name "$($labPrefix.ToLower())storage" `
		        -Type Standard_LRS `
		        -Location $Location
	        Write-Host "Done" -ForegroundColor Green
} 
catch {
    Write-Host "Oh no...Looks like a storage account named ""$($labPrefix)storage"" may already exists -  Exiting..." -ForegroundColor Red
    #Write-Host "Error returned - $_.Exception.Message"
    Break
    }	
}
else { 
    Write-Host "Storage account already exists. Moving on..." -ForegroundColor DarkGray
    $STORAGE = Get-AzureRmStorageAccount -ResourceGroupName $ResourceGroupName | ? {$_.StorageAccountName -eq "$($labPrefix)storage"}
}


############################################ VM NAME, IP, Size, and SKU, are defined below. Add VMs as necessary ######################################
############################################ Only chnage the last octect, so to the right of last decimal #############################################

#Create DC-01 VM - # Best kept unique if poss, as will allow to use for RDP access, instead of public IP 
#===========================
New-AzureLabWindowsServerVM `
    -VMName $DCName `
    -Location $Location `
    -ResourceGroupName $ResourceGroupName `
    -VNETId $VNETSubID `
    -VNETSGId $INTVNETSG.Id `
    -VMSize "Standard_A1" `
    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.50") `
    -LocalAdmin $ForestCreds `
    -SKU "2016-datacenter-smalldisk" `
    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString()

#Create ADFS-01 VM
#=======================
New-AzureLabWindowsServerVM `
    -VMName "ADFS-01" `
    -Location $Location `
    -ResourceGroupName $ResourceGroupName `
    -VNETId $VNETSubID `
    -VNETSGId $INTVNETSG.Id `
    -VMSize "Standard_A1" `
    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.51") `
    -LocalAdmin $Credentials `
    -SKU "2016-datacenter-smalldisk" `
    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString() `
    -JoinDomain -DomainName $ADForestName -DomainAdmin $ForestCreds

#Create WAP-01 VM
#=================
New-AzureLabWindowsServerVM `
    -VMName "WAP-01" `
    -Location $Location `
    -ResourceGroupName $ResourceGroupName `
    -VNETId $VNETSubID `
    -VNETSGId $INTVNETSG.Id `
    -VMSize "Standard_A1" `
    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.52") `
    -LocalAdmin $Credentials `
    -SKU "2016-datacenter-smalldisk" `
    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString() `
    -JoinDomain -DomainName $ADForestName -DomainAdmin $ForestCreds
	
#Create MFA-01 VM
#=================
#New-AzureLabWindowsServerVM `
#    -VMName "MFA-01" `
#    -Location $Location `
#    -ResourceGroupName $ResourceGroupName `
#    -VNETId $VNETSubID `
#    -VNETSGId $INTVNETSG.Id `
#    -VMSize "Standard_A1" `
#    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.53") `
#    -LocalAdmin $Credentials `
#    -SKU "2012-r2-datacenter-smalldisk" `
#    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString() `
#    -JoinDomain -DomainName $ADForestName -DomainAdmin $ForestCreds
	
#Create MFA-02 VM
#=================
#New-AzureLabWindowsServerVM `
#    -VMName "MFA-02" `
#    -Location $Location `
#    -ResourceGroupName $ResourceGroupName `
#    -VNETId $VNETSubID `
#    -VNETSGId $INTVNETSG.Id `
#    -VMSize "Standard_A1" `
#    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.54") `
#    -LocalAdmin $Credentials `
#    -SKU "2012-r2-datacenter-smalldisk" `
#    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString() `
#    -JoinDomain -DomainName $ADForestName -DomainAdmin $ForestCreds 

#Create APP-01 VM
#==================
#New-AzureLabWindowsServerVM `
#    -VMName "APP-01" `
#    -Location $Location `
#    -ResourceGroupName $ResourceGroupName `
#    -VNETId $VNETSubID `
#    -VNETSGId $INTVNETSG.Id `
#    -VMSize "Standard_A1" `
#    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.60") `
#    -LocalAdmin $Credentials `
#    -SKU "2012-r2-datacenter-smalldisk" `
#    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString() `
#    -JoinDomain -DomainName $ADForestName -DomainAdmin $ForestCreds
	
#Create SUSE VM
#==================
#New-AzureLabWindowsServerVM `
#    -VMName "SUSE-01" `
#    -Location $Location `
#    -ResourceGroupName $ResourceGroupName `
#    -VNETId $VNETSubID `
#    -VNETSGId $INTVNETSG.Id `
#    -VMSize "Standard_A1" `
#    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.61") `
#    -LocalAdmin $Credentials `
#    -SKU "11-SP4" `
#    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString()

#Create RDS-01 VM
#==================
#New-AzureLabWindowsServerVM `
#    -VMName "RDS-01" `
#    -Location $Location `
#    -ResourceGroupName $ResourceGroupName `
#    -VNETId $VNETSubID `
#    -VNETSGId $INTVNETSG.Id `
#    -VMSize "Standard_A1" `
#    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.64") `
#    -LocalAdmin $Credentials `
#    -SKU "2012-r2-datacenter-smalldisk" `
#    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString() `
#    -JoinDomain -DomainName $ADForestName -DomainAdmin $ForestCreds
	
#Create RDS-02 VM
#==================
#New-AzureLabWindowsServerVM `
#    -VMName "RDS-02" `
#    -Location $Location `
#    -ResourceGroupName $ResourceGroupName `
#    -VNETId $VNETSubID `
#    -VNETSGId $INTVNETSG.Id `
#    -VMSize "Standard_A1" `
#    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.65") `
#    -LocalAdmin $Credentials `
#    -SKU "2012-r2-datacenter-smalldisk" `
#    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString() `
#    -JoinDomain -DomainName $ADForestName -DomainAdmin $ForestCreds

#Create NDES-01 VM
#==================
#New-AzureLabWindowsServerVM `
#    -VMName "NDES-01" `
#    -Location $Location `
#    -ResourceGroupName $ResourceGroupName `
#    -VNETId $VNETSubID `
#    -VNETSGId $INTVNETSG.Id `
#    -VMSize "Standard_A1" `
#    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.66") `
#    -LocalAdmin $Credentials `
#    -SKU "2012-r2-datacenter-smalldisk" `
#    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString() `
#    -JoinDomain -DomainName $ADForestName -DomainAdmin $ForestCreds
	
#Create PINGFed-01 VM
#==================
#New-AzureLabWindowsServerVM `
#    -VMName "PINGFed-01" `
#    -Location $Location `
#    -ResourceGroupName $ResourceGroupName `
#    -VNETId $VNETSubID `
#    -VNETSGId $INTVNETSG.Id `
#    -VMSize "Standard_A1" `
#    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.67") `
#    -LocalAdmin $Credentials `
#    -SKU "2012-r2-datacenter-smalldisk" `
#    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString() `
#    -JoinDomain -DomainName $ADForestName -DomainAdmin $ForestCreds

#Create TMG VM
#==================
#New-AzureLabWindowsServerVM `
#    -VMName "TMG-01" `
#    -Location $Location `
#    -ResourceGroupName $ResourceGroupName `
#    -VNETId $VNETSubID `
#    -VNETSGId $INTVNETSG.Id `
#    -VMSize "Standard_A1" `
#    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.68") `
#    -LocalAdmin $Credentials `
#    -SKU "2008-R2-SP1-smalldisk" `
#    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString() `
#    -JoinDomain -DomainName $ADForestName -DomainAdmin $ForestCreds

#Create 2012 VM
#==================
#New-AzureLabWindowsServerVM `
#    -VMName "ADFS-2012" `
#    -Location $Location `
#    -ResourceGroupName $ResourceGroupName `
#    -VNETId $VNETSubID `
#    -VNETSGId $INTVNETSG.Id `
#    -VMSize "Standard_A1" `
#    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.69") `
#    -LocalAdmin $Credentials `
#    -SKU "2012-datacenter-smalldisk" `
#    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString() `
#    -JoinDomain -DomainName $ADForestName -DomainAdmin $ForestCreds

#Create EXCH16-01 VM
#=================
New-AzureLabWindowsServerVM `
    -VMName "EXCH16-01" `
    -Location $Location `
    -ResourceGroupName $ResourceGroupName `
    -VNETId $VNETSubID `
    -VNETSGId $INTVNETSG.Id `
    -VMSize "Standard_D3_v2" `
    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.71") `
    -LocalAdmin $Credentials `
    -SKU "2012-r2-datacenter-smalldisk" `
    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString() `
    -JoinDomain -DomainName $ADForestName -DomainAdmin $ForestCreds

# Job done, closing out...
Write-Host "`nJob done, press any key to exit..."
#$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
exit
