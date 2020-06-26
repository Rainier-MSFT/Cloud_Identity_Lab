# Globals  
#########################################################################################################

$ResourceGroupOwner = "Rodney"  # Name of resource group owner - Must be unique within a subscription or will prompt to update an exisiting Resource Group
$labPrefix = "Contoso"  # Must be unique & and alphanumeric only, to support Storage account naming convention
$DCName = "DC-01"   
$ADForestName = "contoso.com"
$VNetIPBlock = "192.168.0.0/24" # Try and avoid overlapping between VNets in different RGs within a subscription, by occupying diffrent 3rd octet if poss
$LANSubnetIPBlock = "192.168.0.0/25" # Provide 108 hosts, leaving some for GW SNet

## - Some resources such as automation accounts are defined by name and can only exist once, Azure wide. Therefore Lab prefix must be different for every new enviroment being spun-up.
## - Script assumes that only one VNET exists for the enviroment, per RG
## - When choosing region be aware that UK South as a new region is fairly new, so runs somewhat leaner that other regions for now. Consider selecting Western EU instead

#########################################################################################################

#Set-PSDebug -Trace 1 -step # Set-PSDebug -Trace 0
#$DebugPreference="Continue"

#########################################################################################################

[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
$host.ui.RawUI.WindowTitle = "Cloud Identity Lab"

CLS
New-Item -path "$env:APPDATA\Windows Azure Powershell" -type directory -ErrorAction SilentlyContinue | Out-Null
Set-Content -path "$env:APPDATA\Windows Azure Powershell\AzureDataCollectionProfile.json" -value '{"enableAzureDataCollection":false}'

## Check if elevated
Write-Host "`n[Pre-req]:" -ForegroundColor Yellow -NoNewline
Write-Host " - Check if session is elevated " -NoNewline
if (-not ([bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544"))) {
    Write-Host "Not running as admin so exiting...`n" -ForegroundColor DarkGray
    exit
} else {
    Write-Host "Done" -ForegroundColor Green
}

## RM module check
Write-Host "`n[Pre-req]:" -ForegroundColor Yellow -NoNewline
Write-Host " - Check for AzureRM module v.5 " -NoNewline
if ((Get-InstalledModule -Name "AzureRm" -MinimumVersion 5.0 -ErrorAction SilentlyContinue) -eq $null) { 
    Try {
        Write-Host "Update required" -ForegroundColor Green       
        Write-Host "`n[Pre-req]:" -ForegroundColor Yellow -NoNewline
        Write-Host " - Installing AzureRM module...." -NoNewline
        Install-module AzureRM -AllowClobber
        Write-Host "Done" -ForegroundColor Green
        Write-Host "`n[MAIN]:" -ForegroundColor Yellow -NoNewline
        write-Host " - Installing AzureRMStorage module...." -NoNewline
        Install-module AzureRM.storage
        Write-Host "Done" -ForegroundColor Green 
        }
    catch 
        {
        Write-Host "Unable to install required modules. Exiting" -ForegroundColor Red
        Exit
        }
}    else {
        Write-Host "Done" -ForegroundColor Green
}

#AuthN to Azure
#======================================
Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
Write-Host " - Login with a Global Administrator account....`n" -NoNewline
if ([string]::IsNullOrEmpty($(Get-AzureRmContext).Account)) {Login-AzureRmAccount}

#Subsciption picker
Try
{       
    Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
    Write-Host " - Querying account for subscriptions...." -NoNewline
    [Environment]::NewLine
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

Function New-AzureLabVM {
    param(
        [Parameter(Mandatory=$true)][string]$VMName,
        [Parameter(Mandatory=$true)][string]$Location,
        [Parameter(Mandatory=$true)][string]$ResourceGroupName,
        [Parameter(Mandatory=$true)][string]$VNETId,
        [Parameter(Mandatory=$true)][string]$VNETSGId,
        [Parameter(Mandatory=$true)][string]$VMSize,
        [Parameter(Mandatory=$true)][string]$PrivateIP,
        [Parameter(Mandatory=$true)][PSCredential]$LocalAdmin,
        [Parameter(Mandatory=$false)][string]$PublisherName,
        [Parameter(Mandatory=$false)][string]$Offer,
        [Parameter(Mandatory=$true)][string]$SKU,
        [Parameter(Mandatory=$true)][string]$Version,
        [Parameter(Mandatory=$true)][string]$StorageBlobURI,
        [switch]$JoinDomain,
        [string]$DomainName,
        [PSCredential]$DomainAdmin
    )
        Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
        Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
        Write-Host " - Querying VM status...." -NoNewline
	    if(-Not (Get-AzureRmResource -ODataQuery "`$filter=resourcetype eq 'Microsoft.Compute/virtualMachines' and resourcegroup eq '$ResourceGroupName' and name eq '$VMName'")) {
            Write-Host "Done" -ForegroundColor Green 

            #Create Dynamic Public IP Interface
            #==================================
            Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
            Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
            Write-Host " - Creating Public IP...." -NoNewline
			if(-Not (Get-AzureRmResource -ODataQuery "`$filter=resourcetype eq 'Microsoft.Network/publicIPAddresses' and resourcegroup eq '$ResourceGroupName' and name eq '$($VMName)-public-ip'")) {
				try { 
                     $PIP = New-AzureRmPublicIpAddress -WA 0 `
					-Name "$($VMName)-public-ip" `
					-ResourceGroupName $ResourceGroupName `
					-Location $Location `
					-DomainNameLabel ($VMName + "-" + $labPrefix).ToLower() `
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
			if(-Not (Get-AzureRmResource -ODataQuery "`$filter=resourcetype eq 'Microsoft.Network/networkinterfaces' and resourcegroup eq '$ResourceGroupName' and name eq '$($VMName)-nic'")) {
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
            if (([string]::IsNullOrEmpty($PublisherName)) -or ([string]::IsNullOrEmpty($Offer))) {
                    $VM = Set-AzureRmVMSourceImage -VM $VM -PublisherName MicrosoftWindowsServer -Offer WindowsServer -Skus $SKU -Version $Version -WA 0
            } else {
                    $VM = Set-AzureRmVMSourceImage -VM $VM -PublisherName $PublisherName -Offer $Offer -Skus $SKU -Version $Version -WA 0
            }
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

Import-Module BitsTransfer
Start-BitsTransfer -Source "https://download.microsoft.com/download/B/0/0/B00291D0-5A83-4DE7-86F5-980BC00DE05A/AzureADConnect.msi" -Destination "C:\Users\Public\Desktop\Install Azure AD Connect.msi"

$Shell = New-Object -ComObject ("WScript.Shell")
$ShortCut = $Shell.CreateShortcut($env:USERPROFILE + "\Desktop\Azure AD Connect.lnk")
$ShortCut.TargetPath = "C:\Program Files (x86)\Internet Explorer\iexplore.exe"
$ShortCut.Arguments = "https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/AzureADConnect"
$ShortCut.WorkingDirectory = "C:\Program Files (x86)\Internet Explorer";
$ShortCut.WindowStyle = 1;
$ShortCut.IconLocation = "%SystemRoot%\system32\SHELL32.dll, 238";
$ShortCut.Save()

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
                    Write-Host " - Uploading automation script to container...." -NoNewline
                    Set-AzureStorageBlobContent -Container "scripts" -File $env:TEMP\New-Forest.ps1 -Blob "New-Forest.ps1" -Context $StorageContext -force | out-null
                    Write-Host "Done" -ForegroundColor Green
                                
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
                    Write-Host " - Provisioning VM with roles and features...." -NoNewline
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

Import-Module BitsTransfer
Start-BitsTransfer -Source "https://download.microsoft.com/download/9/F/5/9F53F124-C990-42D2-8A32-6D352A67762B/AdHealthAdfsAgentSetup.exe" -Destination "C:\Users\Public\Desktop\Install Connect Health.exe"

Stop-Transcript

#Schedule Reboot
Start-Sleep -Seconds 60
Restart-Computer -ComputerName . -Force 
'@ 

                    #Push script
                    #============
                    Write-Host "Done" -Foregroundcolor Green
                    $RolesScript | Out-File $env:TEMP\ADFS-Role.ps1 -Force
                    Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Uploading automation script to container...." -NoNewline
                    Set-AzureStorageBlobContent -Container "scripts" -File $env:TEMP\ADFS-Role.ps1 -Blob "ADFS-Role.ps1" -Context $StorageContext -force | out-null
                    Write-Host "Done" -Foregroundcolor Green

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
                    Write-Host " - Provisioning VM with roles and features...." -NoNewline
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

Import-Module BitsTransfer
Start-BitsTransfer -Source "https://download.microsoft.com/download/9/F/5/9F53F124-C990-42D2-8A32-6D352A67762B/AdHealthAdfsAgentSetup.exe" -Destination "C:\Users\Public\Desktop\Install Connect Health.exe"

Stop-Transcript

#Schedule Reboot
Start-Sleep -Seconds 60
Restart-Computer -ComputerName . -Force 
'@ 

                    #Push script
                    #============
                    Write-Host "Done" -Foregroundcolor Green
                    $RolesScript | Out-File $env:TEMP\WAP-Role.ps1 -Force
                    Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Uploading script to container...." -NoNewline
                    Set-AzureStorageBlobContent -Container "scripts" -File $env:TEMP\WAP-Role.ps1 -Blob "WAP-Role.ps1" -Context $StorageContext -force | out-null
                    Write-Host "Done" -Foregroundcolor Green

                    #Add custom script to VM
                    #=======================
                    Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
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
                    Write-Host " - Provisioning VM with roles and features...." -NoNewline
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
$ShortCut = $Shell.CreateShortcut("C:\Users\Public\Desktop\MFAServer Blade.lnk")
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
                    Write-Host "Done" -Foregroundcolor Green
                    $RolesScript | Out-File $env:TEMP\MFA-Role.ps1 -Force
                    Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Uploading script to container...." -NoNewline
                    Set-AzureStorageBlobContent -Container "scripts" -File $env:TEMP\MFA-Role.ps1 -Blob "MFA-Role.ps1" -Context $StorageContext -force | out-null
                    Write-Host "Done" -Foregroundcolor Green

                    #Add custom script to VM
                    #=======================
                    Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
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
                    Write-Host " - Provisioning VM with roles and features...." -NoNewline
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

Stop-Transcript

#Schedule Reboot
Start-Sleep -Seconds 60
Restart-Computer -ComputerName . -Force 
'@ 

                    #Push script
                    #============
                    Write-Host "Done" -Foregroundcolor Green
                    $RolesScript | Out-File $env:TEMP\TMG-Role.ps1 -Force
                    Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Uploading script to container...." -NoNewline
                    Set-AzureStorageBlobContent -Container "scripts" -File $env:TEMP\TMG-Role.ps1 -Blob "TMG-Role.ps1" -Context $StorageContext -force | out-null
                    Write-Host "Done" -Foregroundcolor Green

                    #Add custom script to VM
                    #=======================
                    Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
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
                    Write-Host " - Provisioning VM with roles and features...." -NoNewline
                    $RolesScript = 
@'

$logDirectory = "C:\logs"
New-Item -ItemType Directory -Path $logDirectory -Force
Start-Transcript -Path "$logDirectory\Roles.log"

Import-Module servermanager
Add-WindowsFeature RDS-RD-Server,RDS-Licensing,RDS-Licensing-UI,RSAT-RDS-Licensing-Diagnosis-UI,RDS-RD-Server,RDS-Gateway,RDS-Web-Access,RDS-Connection-Broker

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
                    Write-Host "Done" -Foregroundcolor Green
                    $RolesScript | Out-File $env:TEMP\RDS-Role.ps1 -Force
                    Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Uploading script to container...." -NoNewline
                    Set-AzureStorageBlobContent -Container "scripts" -File $env:TEMP\RDS-Role.ps1 -Blob "RDS-Role.ps1" -Context $StorageContext -force | out-null
                    Write-Host "Done" -Foregroundcolor Green

                    #Add custom script to VM
                    #=======================
                    Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
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
                    if (($VMName -like "*SP*") -and ($Offer -eq "MicrosoftSharePointServer") -and ($SKU -eq "2016") -or ($SKu -eq "2013")) {
                    #Create Roles and Features script
                    #================================
                    Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Provisioning VM with roles and features...." -NoNewline
                    $RolesScript = 
@'

$logDirectory = "C:\logs"
New-Item -ItemType Directory -Path $logDirectory -Force
Start-Transcript -Path "$logDirectory\Roles.log"

$AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
$UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0

Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 00000000d:
Copy-Item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft SharePoint 2013 Products\*.*" -Destination "C:\Users\Public\Desktop\"
Copy-Item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft SharePoint 2016 Products\*.*" -Destination "C:\Users\Public\Desktop\"

Stop-Transcript

#Schedule Reboot
Start-Sleep -Seconds 60
Restart-Computer -ComputerName . -Force 
'@ 

                    #Push script
                    #============
                    Write-Host "Done" -Foregroundcolor Green
                    $RolesScript | Out-File $env:TEMP\SP-Role.ps1 -Force
                    Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Uploading script to container...." -NoNewline
                    Set-AzureStorageBlobContent -Container "scripts" -File $env:TEMP\SP-Role.ps1 -Blob "SP-Role.ps1" -Context $StorageContext -force | out-null
                    Write-Host "Done" -Foregroundcolor Green

                    #Add custom script to VM
                    #=======================
                    Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Adding custom extension to VM...." -NoNewline
                    $Ext = Set-AzureRmVMCustomScriptExtension -WA 0 `
                           -ResourceGroupName $ResourceGroupName `
                           -VMName $VMName `
                           -Name "$($labPrefix)-Roles" `
                           -Location $VMInfo.Location `
                           -StorageAccountName $STORAGE.StorageAccountName `
                           -StorageAccountKey $Key `
                           -FileName "SP-Role.ps1" `
                           -ContainerName "scripts" #-Verbose
                    Write-Host "Done" -ForegroundColor Green
                    }
                    elseif ($VMName -like "*PINGACC*") {
                    
                    #Create Roles and Features script
                    #================================
                    Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Provisioning VM with roles and features...." -NoNewline
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

$Shell = New-Object -ComObject ("WScript.Shell")
$ShortCut = $Shell.CreateShortcut("C:\Users\Public\Desktop\Start.Here.Java.lnk")
$ShortCut.TargetPath = "C:\Program Files (x86)\Internet Explorer\iexplore.exe"
$ShortCut.Arguments = "https://www.oracle.com/technetwork/java/javase/downloads/jre8-downloads-2133155.html"
$ShortCut.WorkingDirectory = "C:\Program Files (x86)\Internet Explorer";
$ShortCut.WindowStyle = 1;
$ShortCut.IconLocation = "iexplore.exe, 0";
$ShortCut.Save()

$Shell = New-Object -ComObject ("WScript.Shell")
$ShortCut = $Shell.CreateShortcut("C:\Users\Public\Desktop\Then PING Access.lnk")
$ShortCut.TargetPath = "C:\Program Files (x86)\Internet Explorer\iexplore.exe"
$ShortCut.Arguments = "https://www.pingidentity.com/en/resources/downloads/pingaccess/windows.html"
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
                    Write-Host "Done" -Foregroundcolor Green
                    $RolesScript | Out-File $env:TEMP\PINGACC-Role.ps1 -Force
                    Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Uploading script to container...." -NoNewline
                    Set-AzureStorageBlobContent -Container "scripts" -File $env:TEMP\PINGACC-Role.ps1 -Blob "PINGACC-Role.ps1" -Context $StorageContext -force | out-null
                    Write-Host "Done" -Foregroundcolor Green

                    #Add custom script to VM
                    #=======================
                    Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Adding custom extension to VM...." -NoNewline
                    $Ext = Set-AzureRmVMCustomScriptExtension -WA 0 `
                           -ResourceGroupName $ResourceGroupName `
                           -VMName $VMName `
                           -Name "$($labPrefix)-Roles" `
                           -Location $VMInfo.Location `
                           -StorageAccountName $STORAGE.StorageAccountName `
                           -StorageAccountKey $Key `
                           -FileName "PINGACC-Role.ps1" `
                           -ContainerName "scripts" #-Verbose
                    Write-Host "Done" -ForegroundColor Green
                    }
                    elseif ($VMName -like "*EXCH*") {
                    
                    #Create Roles and Features script
                    #================================
                    Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Provisioning VM with roles and features...." -NoNewline
                    $RolesScript = 
@'

$logDirectory = "C:\logs"
New-Item -ItemType Directory -Path $logDirectory -Force
Start-Transcript -Path "$logDirectory\Roles.log"

Import-Module servermanager
Install-WindowsFeature AS-HTTP-Activation, Desktop-Experience, NET-Framework-45-Features, RPC-over-HTTP-proxy, RSAT-Clustering, RSAT-Clustering-CmdInterface, RSAT-Clustering-Mgmt, RSAT-Clustering-PowerShell, Web-Mgmt-Console, WAS-Process-Model, Web-Asp-Net45, Web-Basic-Auth, Web-Client-Auth, Web-Digest-Auth, Web-Dir-Browsing, Web-Dyn-Compression, Web-Http-Errors, Web-Http-Logging, Web-Http-Redirect, Web-Http-Tracing, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Lgcy-Mgmt-Console, Web-Metabase, Web-Mgmt-Console, Web-Mgmt-Service, Web-Net-Ext45, Web-Request-Monitor, Web-Server, Web-Stat-Compression, Web-Static-Content, Web-Windows-Auth, Web-WMI, Windows-Identity-Foundation, RSAT-ADDS-Tools, server-media-foundation

Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

$AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
$UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0

Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 00000000

$Shell = New-Object -ComObject ("WScript.Shell")
$ShortCut = $Shell.CreateShortcut("C:\Users\Public\Desktop\Download UCMA Pre Req.lnk")
$ShortCut.TargetPath = "C:\Program Files (x86)\Internet Explorer\iexplore.exe"
$ShortCut.Arguments = "https://download.microsoft.com/download/2/C/4/2C47A5C1-A1F3-4843-B9FE-84C0032C61EC/UcmaRuntimeSetup.exe"
$ShortCut.WorkingDirectory = "C:\Program Files (x86)\Internet Explorer";
$ShortCut.WindowStyle = 1;
$ShortCut.IconLocation = "iexplore.exe, 0";
$ShortCut.Save()

$Shell = New-Object -ComObject ("WScript.Shell")
$ShortCut = $Shell.CreateShortcut("C:\Users\Public\Desktop\Exchange Setup.lnk")
$ShortCut.TargetPath = "C:\Program Files (x86)\Internet Explorer\iexplore.exe"
$ShortCut.Arguments = "https://docs.microsoft.com/en-us/exchange/plan-and-deploy/deploy-new-installations/create-azure-test-environments?view=exchserver-2019#install-exchange"
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
                    Write-Host "Done" -Foregroundcolor Green
                    $RolesScript | Out-File $env:TEMP\EXCH-Role.ps1 -Force
                    Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Uploading script to container...." -NoNewline
                    Set-AzureStorageBlobContent -Container "scripts" -File $env:TEMP\EXCH-Role.ps1 -Blob "EXCH-Role.ps1" -Context $StorageContext -force | out-null
                    Write-Host "Done" -Foregroundcolor Green

                    #Add custom script to VM
                    #=======================
                    Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Adding custom extension to VM...." -NoNewline
                    $Ext = Set-AzureRmVMCustomScriptExtension -WA 0 `
                           -ResourceGroupName $ResourceGroupName `
                           -VMName $VMName `
                           -Name "$($labPrefix)-Roles" `
                           -Location $VMInfo.Location `
                           -StorageAccountName $STORAGE.StorageAccountName `
                           -StorageAccountKey $Key `
                           -FileName "EXCH-Role.ps1" `
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
if(-not (Get-AzureRmResource -ODataQuery "`$filter=resourcetype eq 'Microsoft.Automation/automationAccounts' and resourcegroup eq '$ResourceGroupName' and name eq '$($labPrefix)-aa'" -WA 0)) {
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
Write-Host " RDP to VMs " -ForegroundColor Cyan -NoNewline
Write-Host " - Generating Internal VNET Ruleset...." -NoNewline
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
Write-Host " 443 to WAP " -ForegroundColor Cyan -NoNewline
Write-Host " - Generating Internal VNET Ruleset...." -NoNewline
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
Write-Host " 49443 to WAP " -ForegroundColor Cyan -NoNewline
Write-Host " - Generating Internal VNET Ruleset...." -NoNewline
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
if(-not (Get-AzureRmResource -ODataQuery "`$filter=resourcetype eq 'Microsoft.Network/networkSecurityGroups' and resourcegroup eq '$ResourceGroupName' and name eq '$($labPrefix)-Int-NSG'" -ea SilentlyContinue -WA 0)) {
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
if (-not (Get-AzureRmResource -ODataQuery "`$filter=resourcetype eq 'Microsoft.Network/virtualNetworks' and resourcegroup eq '$ResourceGroupName' and name eq '$($labPrefix)-VNET'" -WA 0)) {
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

#Create Shared Storage Account
#=============================
Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
Write-Host " - Creating Shared Storage...." -NoNewline
if (-not (Get-AzureRmResource -ODataQuery "`$filter=resourcetype eq 'Microsoft.Storage/storageAccounts' and resourcegroup eq '$ResourceGroupName' and name eq '$($labPrefix)storage'" -WA 0)) {
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
    Write-Host "Please use a different Oh no...Looks like a storage account named ""$($labPrefix)storage"" may already exists -  Exiting..." -ForegroundColor Red
    Break
    }	
}
else { 
    Write-Host "Storage account already exists. Moving on..." -ForegroundColor DarkGray
    $STORAGE = Get-AzureRmStorageAccount -ResourceGroupName $ResourceGroupName | ? {$_.StorageAccountName -eq "$($labPrefix)storage"}
}

# Generate mRemoteNG download link and VM file 
#===============================================================
function Get-AzureRmVmEndpoint 
{ 
    [CmdletBinding()] 
    param( 
        [string]$ResourceGroupName = @()
    ) 
 
    $tempFile = "$env:TEMP\$([System.Guid]::NewGuid().ToString()).rdp" 
 
    $ResourceGroupName | 
    ForEach-Object -Process { 
         $ResourceGroupName = $_
        
        Write-Progress -Activity 'Getting VMs from Resource Group' -Status $ResourceGroupName 
 
        $rgVmName = ( 
            Get-AzureRmVm -ResourceGroupName $ResourceGroupName |  
            Sort-Object -Property Name 
        ).Name | 
        Sort-Object 
 
        if ($rgvmName) 
        { 
            $rgVmName | 
            Where-Object -FilterScript { $_ } | 
            ForEach-Object -Process { 
                $rgVm = $_ 
 
                Write-Progress -Id 1 -Activity 'Getting endpoint from' -Status $rgVm 
 
                Get-AzureRmRemoteDesktopFile -ResourceGroupName $ResourceGroupName -Name $rgvm -LocalPath $tempFile -ErrorAction SilentlyContinue 
                [string]$DNSAddress = (Get-Content -Path $tempFile) -match 'full address:s:' -replace 'full address:s:' 
                ($DNSAddress, $port) = $DNSAddress.Split(':', 2) 
                New-Object -TypeName psobject -Property @{ 
                    ComputerName = $rgVm -as [string] 
                    ResourceGroup = $ResourceGroupName -as [string] 
                    DNSAddress = $DNSAddress -as [string] 
                    Port = $port -as [int] 
                } 
            }
        }
    }

    Remove-Item -Path $tempFile 
}

function New-AzureRmVmRdg 
{ 
    [CmdletBinding()]  
    param( 
 
        [String]$ResourceGroupName = @()
    ) 
     
    function New-RdgXml 
    { 

        # Create Xml doc
 
        [CmdletBinding()]  
        param ( 
            [Alias('Name')] 
            [String]$FileElementName = 'RDG' 
        ) 
 
        $FileElementName = [System.Security.SecurityElement]::Escape($FileElementName) 
 
        @" 
<?xml version="1.0" encoding="utf-8"?>
<RDCMan programVersion="2.7" schemaVersion="3"> 
    <file> 
        <credentialsProfiles /> 
        <properties> 
            <expanded>False</expanded> 
            <name>$FileElementName</name> 
        </properties> 
    </file> 
    <connected /> 
    <favorites /> 
    <recentlyUsed /> 
</RDCMan>     
"@ -as [xml] 
    } 
 
    function Get-RdgGroupInnerXml 
    { 

        # populate Group XmlElement's InnerXML
 
        [CmdletBinding()] 
        param ( 
            [Parameter(Mandatory=$true, Position = 0)] 
            [Alias('Name')] 
            [String]$GroupElementName 
        ) 
 
        $GroupElementName = [System.Security.SecurityElement]::Escape($GroupElementName) 
 
        @" 
<properties> 
    <expanded>False</expanded> 
    <name>$GroupElementName</name> 
</properties> 
"@         
    } 
 
    function Get-ServerElementInnerXml 
    { 

        # populate Server XmlElement's InnerXML
 
        [CmdletBinding()] 
        param ( 
            [Parameter(Mandatory=$true, Position = 0)] 
            [Alias('DNSAddress', 'Name')] 
            [String]$ServerName, 
 
            [Parameter(Position = 1)] 
            [string]$DisplayName 
        ) 
 
        if (!$DisplayName) { $DisplayName = $ServerName } 
 
        $ServerName = [System.Security.SecurityElement]::Escape($ServerName) 
        $DisplayName = [System.Security.SecurityElement]::Escape($DisplayName) 
 
        @" 
<properties> 
    <name>$ServerName</name> 
    <displayName>$DisplayName</displayName> 
</properties> 
"@         
 
    } 
 
    #if ($ResourceGroupName) { $parameters.ResourceGroupName = $ResourceGroupName } 
 
    $azureRmVm = Get-AzureRmVmEndpoint $ResourceGroupName 

    if (!$Path) { $Path = "$home\Desktop\AzureRDG\Azure-$($labPrefix)-VMs.rdg" }  
 
    if (!(Test-Path -Path $Path)) { New-Item -Path $Path -ItemType File -Force } 
 
    $Path = Convert-path -Path $Path 
 
    $rdgXml = New-RdgXml -FileElementName $ResourceGroupName 
    $rootFileNode = $rdgXml.RDCMan.file 
 
        $groupXmlElement = $rdgXml.CreateElement('group') 
 
        $groupXmlElement.InnerXml = Get-RdgGroupInnerXml -GroupElementName $ResourceGroupName 
        $null = $rootFileNode.AppendChild($groupXmlElement) 
 
        $vmObjects =  $azureRmVm | 
        Where-Object ResourceGroup -EQ $ResourceGroupName 
 
        foreach ($vmObject in $vmObjects) 
        { 
            $serverXmlElement = $rdgXml.CreateElement('server') 
            $null = $groupXmlElement.AppendChild($serverXmlElement) 
            $serverXmlElement.InnerXml = Get-ServerElementInnerXml -ServerName $vmObject.DNSAddress -DisplayName $vmObject.ComputerName 
        } 
 
    $rdgXml.Save($Path) | Out-Null

        if (-not(test-path "C:\Program Files (x86)\mRemoteNG\mRemoteNG.ex")) {          
            $Shell = New-Object -ComObject ("WScript.Shell")
            $ShortCut = $Shell.CreateShortcut("C:\Users\Public\Desktop\mRemoteNG.lnk")
            $ShortCut.TargetPath = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
            $ShortCut.Arguments = "https://mremoteng.org/download"
            $ShortCut.WorkingDirectory = "C:\Program Files (x86)\Microsoft\Edge\Application"
            $ShortCut.WindowStyle = 1
            $ShortCut.IconLocation = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe,0"
            $ShortCut.Save()
            } 

            } 
} 

############################################ VM NAME, IP, Size, and SKU, are defined below. Add VMs as necessary ######################################
################################################################ Only chnage the last octect, #########################################################
###################### VM NAMES ARE BEST UNIQUE ACCROSS AZURE REGION AS WOULD ALLOW YOU TO USE DNS FOR RDP INSTEAD PUBLIC IP ##########################
## Host name (VMName) should contain role, so that script logic can apply function specific additions. E.g. MFA server will only be provisioned with MFAServer.exe package if "mfa" is in hostname. Same for RDS, etc. 

# DC-01 VM
#===========================
New-AzureLabVM `
    -VMName $DCName `
    -Location $Location `
    -ResourceGroupName $ResourceGroupName `
    -VNETId $VNETSubID `
    -VNETSGId $INTVNETSG.Id `
    -VMSize "Standard_B2s" `
    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.50") `
    -LocalAdmin $ForestCreds `
    -SKU "2016-datacenter-smalldisk" `
    -Version "latest" `
    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString()

# ADFS-01 VM
#=======================
New-AzureLabVM `
    -VMName "ADFS-01" `
    -Location $Location `
    -ResourceGroupName $ResourceGroupName `
    -VNETId $VNETSubID `
    -VNETSGId $INTVNETSG.Id `
    -VMSize "Standard_B2s" `
    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.52") `
    -LocalAdmin $Credentials `
    -SKU "2019-datacenter-smalldisk" `
    -Version "latest" `
    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString() `
    -JoinDomain -DomainName $ADForestName -DomainAdmin $ForestCreds

# WAP-01 VM
#=================
New-AzureLabVM `
    -VMName "WAP-01" `
    -Location $Location `
    -ResourceGroupName $ResourceGroupName `
    -VNETId $VNETSubID `
    -VNETSGId $INTVNETSG.Id `
    -VMSize "Standard_B2s" `
    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.54") `
    -LocalAdmin $Credentials `
    -SKU "2019-datacenter-smalldisk" `
    -Version "latest" `
    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString() `
    -JoinDomain -DomainName $ADForestName -DomainAdmin $ForestCreds
	
# SP-01 VM ( Sharepoint 2013)
#=======================
#New-AzureLabVM `
#   -VMName "SP-01" `
#   -Location $Location `
#   -ResourceGroupName $ResourceGroupName `
#   -VNETId $VNETSubID `
#   -VNETSGId $INTVNETSG.Id `
#   -VMSize "Standard_D2_v3" `
#   -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.56") `
#   -LocalAdmin $Credentials `
#   -Publisher "MicrosoftSharePoint" `
#   -Offer "MicrosoftSharePointServer" `
#   -SKU "2013" `
#   -Version "latest" `
#   -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString() `
#   -JoinDomain -DomainName $ADForestName -DomainAdmin $ForestCreds

# SQL-01 VM (2016)
#=======================
#New-AzureLabVM `
#    -VMName "SQL16-01" `
#    -Location $Location `
#    -ResourceGroupName $ResourceGroupName `
#    -VNETId $VNETSubID `
#    -VNETSGId $INTVNETSG.Id `
#    -VMSize "Standard_D2_v3" `
#    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.58") `
#    -LocalAdmin $Credentials `
#    -Publisher "MicrosoftSQLServer" `
#    -Offer "SQL2016SP2-WS2016" `
#    -SKU "Standard" `
#    -Version "latest" `
#    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString() `
#    -JoinDomain -DomainName $ADForestName -DomainAdmin $ForestCreds

# SharePoint-01 VM (2016)
#=======================
#New-AzureLabVM `
#    -VMName "SP16-01" `
#    -Location $Location `
#    -ResourceGroupName $ResourceGroupName `
#    -VNETId $VNETSubID `
#    -VNETSGId $INTVNETSG.Id `
#    -VMSize "Standard_D2_v3" `
#    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.60") `
#    -LocalAdmin $Credentials `
#    -Publisher "MicrosoftSharePoint" `
#    -Offer "MicrosoftSharePointServer" `
#    -SKU "2016" `
#    -Version "latest" `
#    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString() `
#    -JoinDomain -DomainName $ADForestName -DomainAdmin $ForestCreds

# MFA-01 VM
#=================
#New-AzureLabVM `
#    -VMName "MFA-01" `
#    -Location $Location `
#    -ResourceGroupName $ResourceGroupName `
#    -VNETId $VNETSubID `
#    -VNETSGId $INTVNETSG.Id `
#    -VMSize "Standard_A1" `
#    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.62") `
#    -LocalAdmin $Credentials `
#    -SKU "2012-r2-datacenter-smalldisk" `
#    -Version "latest" `
#    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString() `
#    -JoinDomain -DomainName $ADForestName -DomainAdmin $ForestCreds
	
# APP-02 VM
#=================
#New-AzureLabVM `
#    -VMName "APP-02" `
#    -Location $Location `
#    -ResourceGroupName $ResourceGroupName `
#    -VNETId $VNETSubID `
#    -VNETSGId $INTVNETSG.Id `
#    -VMSize "Standard_D4_v3" `
#    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.64") `
#    -LocalAdmin $Credentials `
#    -SKU "2012-r2-datacenter" `
#    -Version "latest" `
#    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString() `
#    -JoinDomain -DomainName $ADForestName -DomainAdmin $ForestCreds 

# APP-01 VM
#=================
#New-AzureLabVM `
#    -VMName "APP-01" `
#    -Location $Location `
#    -ResourceGroupName $ResourceGroupName `
#    -VNETId $VNETSubID `
#    -VNETSGId $INTVNETSG.Id `
#    -VMSize "Standard_A1" `
#    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.66") `
#    -LocalAdmin $Credentials `
#    -SKU "2012-r2-datacenter-smalldisk" `
#    -Version "latest" `
#    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString() `
#    -JoinDomain -DomainName $ADForestName -DomainAdmin $ForestCreds
	
# SUSE VM
#==================
#New-AzureLabVM `
#    -VMName "SUSE-01" `
#    -Location $Location `
#    -ResourceGroupName $ResourceGroupName `
#    -VNETId $VNETSubID `
#    -VNETSGId $INTVNETSG.Id `
#    -VMSize "Standard_A1" `
#    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.68") `
#    -LocalAdmin $Credentials `
#    -SKU "11-SP4" `
#    -Version "latest" `
#    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString()

# RDS-01 VM
#==================
#New-AzureLabVM `
#    -VMName "RDS-01" `
#    -Location $Location `
#    -ResourceGroupName $ResourceGroupName `
#    -VNETId $VNETSubID `
#    -VNETSGId $INTVNETSG.Id `
#    -VMSize "Standard_B2ms" `
#    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.70") `
#    -LocalAdmin $Credentials `
#    -SKU "2019-datacenter-smalldisk" `
#    -Version "latest" `
#    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString() `
#    -JoinDomain -DomainName $ADForestName -DomainAdmin $ForestCreds
	
# RDS-02 VM
#==================
#New-AzureLabVM `
#    -VMName "RDS-02" `
#    -Location $Location `
#    -ResourceGroupName $ResourceGroupName `
#    -VNETId $VNETSubID `
#    -VNETSGId $INTVNETSG.Id `
#    -VMSize "Standard_A1" `
#    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.72") `
#    -LocalAdmin $Credentials `
#    -SKU "2012-r2-datacenter-smalldisk" `
#    -Version "latest" `
#    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString() `
#    -JoinDomain -DomainName $ADForestName -DomainAdmin $ForestCreds

# NDES-01 VM
#==================
#New-AzureLabVM `
#    -VMName "NDES-01" `
#    -Location $Location `
#    -ResourceGroupName $ResourceGroupName `
#    -VNETId $VNETSubID `
#    -VNETSGId $INTVNETSG.Id `
#    -VMSize "Standard_A1" `
#    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.74") `
#    -LocalAdmin $Credentials `
#    -SKU "2012-r2-datacenter-smalldisk" `
#    -Version "latest" `
#    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString() `
#    -JoinDomain -DomainName $ADForestName -DomainAdmin $ForestCreds

# PINGACC-01 VM
#=======================
#New-AzureLabVM `
#    -VMName "PINGACC-01" `
#    -Location $Location `
#    -ResourceGroupName $ResourceGroupName `
#    -VNETId $VNETSubID `
#    -VNETSGId $INTVNETSG.Id `
#    -VMSize "Standard_A1" `
#    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.75") `
#    -LocalAdmin $Credentials `
#    -SKU "2012-r2-datacenter-smalldisk" `
#    -Version "latest" `
#    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString() `
#    -JoinDomain -DomainName $ADForestName -DomainAdmin $ForestCreds

# PINGFed-01 VM
#==================
#New-AzureLabVM `
#    -VMName "PINGFed-01" `
#    -Location $Location `
#    -ResourceGroupName $ResourceGroupName `
#    -VNETId $VNETSubID `
#    -VNETSGId $INTVNETSG.Id `
#    -VMSize "Standard_A1" `
#    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.76") `
#    -LocalAdmin $Credentials `
#    -SKU "2012-r2-datacenter-smalldisk" `
#    -Version "latest" `
#    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString() `
#    -JoinDomain -DomainName $ADForestName -DomainAdmin $ForestCreds

# TMG VM
#==================
#New-AzureLabVM `
#    -VMName "TMG-01" `
#    -Location $Location `
#    -ResourceGroupName $ResourceGroupName `
#    -VNETId $VNETSubID `
#    -VNETSGId $INTVNETSG.Id `
#    -VMSize "Standard_A1" `
#    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.78") `
#    -LocalAdmin $Credentials `
#    -SKU "2008-R2-SP1-smalldisk" `
#    -Version "latest" `
#    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString() `
#    -JoinDomain -DomainName $ADForestName -DomainAdmin $ForestCreds

# 2012 VM
#==================
#New-AzureLabVM `
#    -VMName "ADFS-2012" `
#    -Location $Location `
#    -ResourceGroupName $ResourceGroupName `
#    -VNETId $VNETSubID `
#    -VNETSGId $INTVNETSG.Id `
#    -VMSize "Standard_A1" `
#    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.80") `
#    -LocalAdmin $Credentials `
#    -SKU "2012-datacenter-smalldisk" `
#    -Version "latest" `
#    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString() `
#    -JoinDomain -DomainName $ADForestName -DomainAdmin $ForestCreds

# 2012 VM
#==================
#New-AzureLabVM `
#    -VMName "ADFS-PROXY" `
#    -Location $Location `
#    -ResourceGroupName $ResourceGroupName `
#    -VNETId $VNETSubID `
#    -VNETSGId $INTVNETSG.Id `
#    -VMSize "Standard_A1" `
#    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.82") `
#    -LocalAdmin $Credentials `
#    -SKU "2012-datacenter-smalldisk" `
#    -Version "latest" `
#    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString() `
#    -JoinDomain -DomainName $ADForestName -DomainAdmin $ForestCreds

# CRM-01 VM
#==================
#New-AzureLabVM `
#    -VMName "CRM-01" `
#    -Location $Location `
#    -ResourceGroupName $ResourceGroupName `
#    -VNETId $VNETSubID `
#    -VNETSGId $INTVNETSG.Id `
#    -VMSize "Standard_A1" `
#    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.84") `
#    -LocalAdmin $Credentials `
#    -SKU "2012-r2-datacenter-smalldisk" `
#    -Version "latest" `
#    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString() `
#    -JoinDomain -DomainName $ADForestName -DomainAdmin $ForestCreds

# 2008r2-01 VM
#==================
#New-AzureLabVM `
#    -VMName "2008r2-01" `
#    -Location $Location `
#    -ResourceGroupName $ResourceGroupName `
#    -VNETId $VNETSubID `
#    -VNETSGId $INTVNETSG.Id `
#    -VMSize "Standard_A1" `
#    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.86") `
#    -LocalAdmin $Credentials `
#    -SKU "2008-R2-SP1-smalldisk" `
#    -Version "latest" `
#    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString() `
#    -JoinDomain -DomainName $ADForestName -DomainAdmin $ForestCreds

# Microsoft Identity Manager
#==================
#New-AzureLabVM `
#    -VMName "MIM-01" `
#    -Location $Location `
#    -ResourceGroupName $ResourceGroupName `
#    -VNETId $VNETSubID `
#    -VNETSGId $INTVNETSG.Id `
#    -VMSize "Standard_D2_v3" `
#    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.88") `
#    -LocalAdmin $Credentials `
#    -SKU "2012-r2-datacenter" `
#    -Version "latest" `
#    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString() `
#    -JoinDomain -DomainName $ADForestName -DomainAdmin $ForestCreds

# ARR-01 VM
#=================
#New-AzureLabVM `
#    -VMName "ARR-01" `
#    -Location $Location `
#    -ResourceGroupName $ResourceGroupName `
#    -VNETId $VNETSubID `
#    -VNETSGId $INTVNETSG.Id `
#    -VMSize "Standard_A1" `
#    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.91") `
#    -LocalAdmin $Credentials `
#    -SKU "2012-r2-datacenter-smalldisk" `
#    -Version "latest" `
#    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString() `
#    -JoinDomain -DomainName $ADForestName -DomainAdmin $ForestCreds

# Windows 10 - AADJ (Not joined to lcoal domain)
#=======================
#New-AzureLabVM `
#    -VMName "W10-02" `
#    -Location $Location `
#    -ResourceGroupName $ResourceGroupName `
#    -VNETId $VNETSubID `
#    -VNETSGId $INTVNETSG.Id `
#    -VMSize "Standard_B2ms" `
#    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.93") `
#    -LocalAdmin $Credentials `
#    -Publisher "MicrosoftVisualStudio" `
#    -Offer "windows" `
#    -SKU "Windows-10-N-x64" `
#    -Version "latest" `
#    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString() `

# Windows 8.1
#=======================
#New-AzureLabVM `
#    -VMName "W8-01" `
#    -Location $Location `
#    -ResourceGroupName $ResourceGroupName `
#    -VNETId $VNETSubID `
#    -VNETSGId $INTVNETSG.Id `
#    -VMSize "Standard_B2ms" `
#    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.95") `
#    -LocalAdmin $Credentials `
#    -Publisher "MicrosoftVisualStudio" `
#    -Offer "windows" `
#    -SKU "Win81-Ent-N-x64" `
#    -Version "latest" `
#    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString() `

# Windows 7
#=======================
#New-AzureLabVM `
#    -VMName "W7-01" `
#    -Location $Location `
#    -ResourceGroupName $ResourceGroupName `
#    -VNETId $VNETSubID `
#    -VNETSGId $INTVNETSG.Id `
#    -VMSize "Standard_B2ms" `
#    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.97") `
#    -LocalAdmin $Credentials `
#    -Publisher "MicrosoftVisualStudio" `
#    -Offer "windows" `
#    -SKU "Win7-SP1-Ent-N-x64" `
#    -Version "latest" `
#    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString() `

# WAC-01 VM
#==================
#New-AzureLabVM `
#    -VMName "WAC-01" `
#    -Location $Location `
#    -ResourceGroupName $ResourceGroupName `
#    -VNETId $VNETSubID `
#    -VNETSGId $INTVNETSG.Id `
#    -VMSize "Standard_B2ms" `
#    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.99") `
#    -LocalAdmin $Credentials `
#    -SKU "2019-datacenter-smalldisk" `
#    -Version "latest" `
#    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString() `
#    -JoinDomain -DomainName $ADForestName -DomainAdmin $ForestCreds

# EXCH16-16 VM
#==================
#New-AzureLabVM `
#    -VMName "EXCH-16" `
#    -Location $Location `
#    -ResourceGroupName $ResourceGroupName `
#    -VNETId $VNETSubID `
#    -VNETSGId $INTVNETSG.Id `
#    -VMSize "Standard_D3_v2" `
#    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.101") `
#    -LocalAdmin $Credentials `
#    -SKU "2012-R2-Datacenter" `
#    -Version "latest" `
#    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString() `
#    -JoinDomain -DomainName $ADForestName -DomainAdmin $ForestCreds

# AADCv2-01 VM
#==================
#New-AzureLabVM `
#    -VMName "AADCv2-01" `
#    -Location $Location `
#    -ResourceGroupName $ResourceGroupName `
#    -VNETId $VNETSubID `
#    -VNETSGId $INTVNETSG.Id `
#    -VMSize "Standard_D3_v2" `
#    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.103") `
#    -LocalAdmin $Credentials `
#    -SKU "2016-datacenter-smalldisk" `
#    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString() `
#    -JoinDomain -DomainName $ADForestName -DomainAdmin $ForestCreds

# EXCH-16 VM
#==================
#New-AzureLabVM `
#    -VMName "EXCH-16" `
#    -Location $Location `
#    -ResourceGroupName $ResourceGroupName `
#    -VNETId $VNETSubID `
#    -VNETSGId $INTVNETSG.Id `
#    -VMSize "Standard_D3_v2" `
#    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.105") `
#    -LocalAdmin $Credentials `
#    -SKU "2016-Datacenter" `
#    -Version "latest" `
#    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString() `
#    -JoinDomain -DomainName $ADForestName -DomainAdmin $ForestCreds

# APP-TEST VM
#==================
#New-AzureLabVM `
#    -VMName "APP-TEST" `
#    -Location $Location `
#    -ResourceGroupName $ResourceGroupName `
#    -VNETId $VNETSubID `
#    -VNETSGId $INTVNETSG.Id `
#    -VMSize "Standard_D3_v2" `
#    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.109") `
#    -LocalAdmin $Credentials `
#    -SKU "2016-Datacenter" `
#    -Version "latest" `
#    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString() `
#    -JoinDomain -DomainName $ADForestName -DomainAdmin $ForestCreds

# Windows 10 - 1709 domain joined
#=======================
#New-AzureLabVM `
#    -VMName "W10-1709-dj" `
#    -Location $Location `
#    -ResourceGroupName $ResourceGroupName `
#    -VNETId $VNETSubID `
#    -VNETSGId $INTVNETSG.Id `
#    -VMSize "Standard_B2ms" `
#    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.111") `
#    -LocalAdmin $Credentials `
#    -Publisher "MicrosoftVisualStudio" `
#    -Offer "windows" `
#    -SKU "Windows-10-N-x64" `
#    -Version "2018.08.17" `
#    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString() `
#    -JoinDomain -DomainName $ADForestName -DomainAdmin $ForestCreds

# Windows 10 - 1709 Not domain joined
#=======================
#New-AzureLabVM `
#    -VMName "W10-1709" `
#    -Location $Location `
#    -ResourceGroupName $ResourceGroupName `
#    -VNETId $VNETSubID `
#    -VNETSGId $INTVNETSG.Id `
#    -VMSize "Standard_B2ms" `
#    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.113") `
#    -LocalAdmin $Credentials `
#    -Publisher "MicrosoftVisualStudio" `
#    -Offer "windows" `
#    -SKU "Windows-10-N-x64" `
#    -Version "2018.08.17" `
#    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString()

# Windows 10 - Latest v. domain joined
#=======================
New-AzureLabVM `
    -VMName "W10-01" `
    -Location $Location `
    -ResourceGroupName $ResourceGroupName `
    -VNETId $VNETSubID `
    -VNETSGId $INTVNETSG.Id `
    -VMSize "Standard_B2ms" `
    -PrivateIP $($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.115") `
    -LocalAdmin $Credentials `
    -Publisher "MicrosoftVisualStudio" `
    -Offer "windows" `
    -SKU "Windows-10-N-x64" `
    -Version "latest" `
    -StorageBlobURI $STORAGE.PrimaryEndpoints.Blob.ToString()
    -JoinDomain -DomainName $ADForestName -DomainAdmin $ForestCreds

# Call RDCMan function
Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
Write-Host " RDP to VMs " -ForegroundColor Cyan -NoNewline
Write-Host " - Generating VM collection for Remote Desktop Manager...." -NoNewline
New-AzureRmVmRdg $ResourceGroupName -WA 0
Write-Host "Done`n" -ForegroundColor Green

# Job done, closing out...
$wshell = New-Object -ComObject Wscript.Shell
$wshell.Popup(" Go ahead and install RDC Manager and import the pre-generated Azure-$($labPrefix)-VMs.rdg file",0," Job complete...",0x0) | Out-Null
invoke-item "$home\Desktop\AzureRDG\"

exit
