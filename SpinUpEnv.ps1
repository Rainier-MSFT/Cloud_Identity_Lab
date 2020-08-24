# Globals  
#########################################################################################################

$ResourceGroupOwner = "Rodney"  # Name of resource group owner - Must be unique within a subscription or will prompt to update an exisiting Resource Group
$labPrefix = "contoso"  # Must be unique & and alphanumeric only, to support Storage account naming constraints. I.e. Must be unique Azure wide and max 21 chars
$DCName = "DC-01"   
$ADForestName = "contoso.com"
$VNetIPBlock = "192.168.0.0/24" # Try and avoid overlapping between VNets in different RGs within a subscription, by occupying diffrent 3rd octet if poss
$LANSubnetIPBlock = "192.168.0.0/25" # Provide 108 hosts, leaving some for GW SNet

## - As storage account name needs to be unique in Azure, script will use lab prefix and append random number if "$labprefix+"storage" name is already used. E.g. Contosostorage
## - Some resources such as automation accounts are defined by name and can only exist once, Azure wide. Therefore Lab prefix must be different for every new enviroment being spun-up.
## - Script assumes that only one VNET exists for the enviroment, per RG

#########################################################################################################

#Set-PSDebug -Trace 1 -step # Set-PSDebug -Trace 0
#$DebugPreference="Continue"
New-Item -path "$env:APPDATA\Windows Azure Powershell" -type directory -ErrorAction SilentlyContinue | Out-Null
Set-Content -path "$env:APPDATA\Windows Azure Powershell\AzureDataCollectionProfile.json" -value '{"enableAzureDataCollection":false}'

Set-Item Env:\SuppressAzurePowerShellBreakingChangeWarnings "true"

#########################################################################################################

CLS

## Check if elevated
Write-Host "`n[Pre-req]:" -ForegroundColor Yellow -NoNewline
Write-Host " - Check if session is elevated...." -NoNewline
if (-not ([bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544"))) {
    Write-Host "Not running as admin so exiting...`n" -ForegroundColor DarkGray
    exit
} else {
    Write-Host "Done" -ForegroundColor Green
}

## Az module check
Write-Host "`n[Pre-req]:" -ForegroundColor Yellow -NoNewline
Write-Host " - Check for Az module...." -NoNewline
if ((Get-InstalledModule -Name "Az" -MinimumVersion 3.0 -ErrorAction SilentlyContinue) -eq $null) { 
    Try {
        Write-Host "Az Module required" -ForegroundColor Green       
        Write-Host "`n[Pre-req]:" -ForegroundColor Yellow -NoNewline
        Write-Host " - Installing Az module...." -NoNewline
        Install-module Az -AllowClobber
        #Enable-AzureRmAlias
        Write-Host "Done" -ForegroundColor Green
        }
    catch 
        {
        Write-Host "Unable to install required Az module. Exiting" -ForegroundColor Red
        Exit
        }
}    else {
        #Enable-AzureRmAlias
        Write-Host "Done" -ForegroundColor Green
}

#Azure authN
#===========
Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
Write-Host " - Login with a Global Administrator account...." -NoNewline
if ([string]::IsNullOrEmpty($(Get-AzContext).Account)) { Connect-Azaccount | Out-Null }
Write-Host "Done" -ForegroundColor Green

#Subsciption picker
#==================
[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
$host.ui.RawUI.WindowTitle = "Cloud Identity Lab"
Try
{       
    Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
    Write-Host " - Enumerating subscriptions...." -NoNewline
	$Subs = Get-AzSubscription -WA SilentlyContinue
    Write-Host "Select target subscription from list" -ForegroundColor cyan
 
    [void][reflection.assembly]::Load('System.Windows.Forms, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')
    [System.Windows.Forms.Application]::EnableVisualStyles();
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
    $formShowmenu.Text = ' Select your subscription...'
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
    Select-AzSubscription –SubscriptionName $var | Out-Null
    Set-AzContext -SubscriptionName $var | Out-Null
    Write-Host "[" -NoNewline
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
	    if(-Not (Get-AzResource -ResourceGroupName $ResourceGroupName -ResourceType "Microsoft.Compute/virtualMachines" -Name $VMName -ErrorAction SilentlyContinue)) {
            Write-Host "Done" -ForegroundColor Green 

            #Create Dynamic Public IP Interface
            #==================================
            Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
            Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
            Write-Host " - Public IP...." -NoNewline
            if(-Not (Get-AzResource -ResourceGroupName $ResourceGroupName -ResourceType "Microsoft.Network/publicIPAddresses" -Name "$($VMName)-public-ip" -ErrorAction SilentlyContinue)) {			
				try { 
                     $PIP = New-AzPublicIpAddress -Name "$($VMName)-public-ip" -ResourceGroupName $ResourceGroupName -Location $Location -DomainNameLabel "$($VMName.ToLower())-$($ResourceGroupName.ToLower())" -AllocationMethod Dynamic
                     $PIP = $PIP.id
				     Write-Host "Done" -ForegroundColor Green }
                catch {
                    Write-Host "Unable to create interface. Exiting" -ForegroundColor DarkGray
                    #Exit
                } }
            else {
				Write-Host "Interface already exists. Moving on" -ForegroundColor DarkGray
                $PIP = (Get-AzPublicIpAddress -ResourceGroupName $ResourceGroupName -Name "$($VMName)-public-ip").Id
			}

            #Create NIC Interface to be attached to VM
            #=========================================
            Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
            Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
            Write-Host " - Net Interface...." -NoNewline
			if(-Not (Get-AzResource -ResourceGroupName $ResourceGroupName -ResourceType "Microsoft.Network/networkinterfaces" -Name "$($VMName)-nic" -ErrorAction SilentlyContinue)) {
                try {
				     $NIC = New-AzNetworkInterface -Name "$($VMName)-nic" -ResourceGroupName $ResourceGroupName -Location $Location -SubnetId $VNETSubID -PrivateIpAddress $PrivateIP -PublicIpAddressId $PIP -NetworkSecurityGroupId $VNETSGId
				     Write-Host "Done" -ForegroundColor Green }
                catch {
                    Write-Host "Unable to create interface. Exiting" -ForegroundColor DarkGray
                    Exit } 
            }
            else {
				Write-Host "Interface already exists. Moving on" -ForegroundColor DarkGray
				$NIC = Get-AzNetworkInterface -ResourceGroupName $ResourceGroupName -Name "$($VMName)-nic"
			}

            #Construct VM Configuration Object
            #=================================
            Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
            Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
            Write-Host " - VM Configuration...." -NoNewline
            $OSDISKURI = $StorageBlobURI + "vhds/" + $VMName + "sys.vhd"
            $VM = New-AzVMConfig -VMName $VMName -VMSize $VMSize -WA 0
            $VM = Set-AzVMOperatingSystem -VM $VM -Windows -ComputerName $VMName -Credential $LocalAdmin -ProvisionVMAgent -EnableAutoUpdate -WinRMHttp -WA 0         
            if (([string]::IsNullOrEmpty($PublisherName)) -or ([string]::IsNullOrEmpty($Offer))) {
                    $VM = Set-AzVMSourceImage -VM $VM -PublisherName MicrosoftWindowsServer -Offer WindowsServer -Skus $SKU -Version $Version -WA 0
            } else {
                    $VM = Set-AzVMSourceImage -VM $VM -PublisherName $PublisherName -Offer $Offer -Skus $SKU -Version $Version -WA 0
            }
            $VM = Add-AzVMNetworkInterface -VM $VM -Id $NIC.Id -WA 0
            $VM = Set-AzVMOSDisk -VM $VM -Name "$($VMName)sys" -vhd $OSDISKURI -CreateOption fromImage -WA 0
            Write-Host "Done" -ForegroundColor Green
         
            #Create VM
            #=========
            Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
            Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
            #Write-Host " - Provision VM....`n" -NoNewline
            Write-Host " - Provision VM...." -NoNewline
            New-AzVM -ResourceGroupName $ResourceGroupName -Location $Location -VM $VM | out-null
            Write-Host "Done" -ForegroundColor Green
        
            #Join Domain if requested
            #========================
            if ($JoinDomain){
                Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
                Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                Write-Host " - Joining to $($domainName) domain....`n" -NoNewline
                Set-AzVMExtension -VMName $VMName -ResourceGroupName $ResourceGroupName -Name "JoinAD" -ExtensionType "JsonADDomainExtension" -Publisher "Microsoft.Compute" -TypeHandlerVersion "1.0" -Location $Location -Settings @{ "Name" = $domainName; "OUPath" = ""; "User" = "$($DomainAdmin.Username)@$domainName"; "Restart" = "true"; "Options" = 3} -ProtectedSettings @{"Password" = "$($DomainAdmin.GetNetworkCredential().Password)"} | out-null
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
                    Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Provisioning AD Forest...." -NoNewline
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
                    Write-Host "Done" -ForegroundColor Green
                     
                    #Push script
                    #============
                    Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Uploading automation script to container...." -NoNewline
                    Set-AzStorageBlobContent -Container "scripts" -File $env:TEMP\New-Forest.ps1 -Blob "New-Forest.ps1" -Context $StorageContext -force | out-null
                    Write-Host "Done" -ForegroundColor Green
                                
                    #Add custom script to DC
                    #=======================
                    Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Adding custom extension...." -NoNewline
                    Set-AzVMCustomScriptExtension -ResourceGroupName $ResourceGroupName -VMName $DCName -Name "$($labPrefix)-Forest" -Location $Location -StorageAccountName $STORAGE.Name -StorageAccountKey $Key -FileName "New-Forest.ps1" -Run "New-Forest.ps1" -ContainerName "scripts" | out-null
                    Write-Host "Done" -ForegroundColor Green
                    
                    #Add Role Tag
                    #============
                    Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Adding VM Role Tag...." -NoNewline
                    Set-AzResource -ResourceGroupName $ResourceGroupName -ResourceType Microsoft.Compute/virtualMachines -ResourceName $VMName -Tag @{ "Role"="CloudIDLab_DC" } -Force | Out-Null
                    Write-Host "Done" -ForegroundColor Green

                    }
            elseif ($VMName -like "*adfs*") {
                   
                    #Create Roles and Features script
                    #================================
                    Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Provisioning roles and features. This might take a while...." -NoNewline
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
                    Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Uploading role script to container...." -NoNewline
                    Set-AzStorageBlobContent -Container "scripts" -File $env:TEMP\ADFS-Role.ps1 -Blob "ADFS-Role.ps1" -Context $StorageContext -force | out-null
                    Write-Host "Done" -Foregroundcolor Green

                    #Add custom script to VM
                    #=======================
                    Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Adding custom extension...." -NoNewline
                    Set-AzVMCustomScriptExtension -ResourceGroupName $ResourceGroupName -VMName $VMName -Name "$($labPrefix)-Roles" -Location $Location -StorageAccountName $STORAGE.Name -StorageAccountKey $Key -FileName "ADFS-Role.ps1" -Run "ADFS-Role.ps1" -ContainerName "scripts" | out-null
                    Write-Host "Done" -ForegroundColor Green
                    
                    #Add Role Tag
                    #============
                    Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Adding VM Role Tag...." -NoNewline
                    Set-AzResource -ResourceGroupName $ResourceGroupName -ResourceType Microsoft.Compute/virtualMachines -ResourceName $VMName -Tag @{ "Role"="CloudIDLab_ADFS" } -Force | Out-Null
                    Write-Host "Done" -ForegroundColor Green
                    }
                    
          elseif ($VMName -like "*wap*") {

                    #Create Roles and Features script
                    #================================
                    Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Provisioning roles and features...." -NoNewline
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
                    Write-Host "[MAIN]: " -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Uploading script to container...." -NoNewline
                    Set-AzStorageBlobContent -Container "scripts" -File $env:TEMP\WAP-Role.ps1 -Blob "WAP-Role.ps1" -Context $StorageContext -force | out-null
                    Write-Host "Done" -Foregroundcolor Green

                    #Add custom script to VM
                    #=======================
                    Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Adding custom extension...." -NoNewline
                    Set-AzVMCustomScriptExtension -ResourceGroupName $ResourceGroupName -VMName $VMName -Name "$($labPrefix)-Roles" -Location $Location -StorageAccountName $STORAGE.Name -StorageAccountKey $Key -FileName "WAP-Role.ps1" -Run "WAP-Role.ps1" -ContainerName "scripts" | out-null
                    Write-Host "Done" -ForegroundColor Green
                    
                    #Add Role Tag
                    #============
                    Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Adding VM Role Tag...." -NoNewline
                    Set-AzResource -ResourceGroupName $ResourceGroupName -ResourceType Microsoft.Compute/virtualMachines -ResourceName $VMName -Tag @{ "Role"="CloudIDLab_WAP" } -Force | Out-Null
                    Write-Host "Done" -ForegroundColor Green        
                    }
                    
                    elseif ($VMName -like "*mfa*") {
                    
                    #Create Roles and Features script
                    #================================
                    Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Provisioning roles and features...." -NoNewline
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
                    Write-Host "[MAIN]: " -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Uploading script to container...." -NoNewline
                    Set-AzStorageBlobContent -Container "scripts" -File $env:TEMP\MFA-Role.ps1 -Blob "MFA-Role.ps1" -Context $StorageContext -force | out-null
                    Write-Host "Done" -Foregroundcolor Green

                    #Add custom script to VM
                    #=======================
                    Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Adding custom extension...." -NoNewline
                    Set-AzVMCustomScriptExtension -ResourceGroupName $ResourceGroupName -VMName $VMName -Name "$($labPrefix)-Roles" -Location $Location -StorageAccountName $STORAGE.Name -StorageAccountKey $Key -FileName "MFA-Role.ps1" -Run "MFA-Role.ps1" -ContainerName "scripts" | out-null
                    Write-Host "Done" -ForegroundColor Green

                    #Add Role Tag
                    #============
                    Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Adding VM Role Tag...." -NoNewline
                    Set-AzResource -ResourceGroupName $ResourceGroupName -ResourceType Microsoft.Compute/virtualMachines -ResourceName $VMName -Tag @{ "Role"="CloudIDLab_MFA" } -Force | Out-Null
                    Write-Host "Done" -ForegroundColor Green        
                    }
                    elseif ($VMName -like "*rds*") 
                    {
                    #Create Roles and Features script
                    #================================
                    Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Provisioning roles and features...." -NoNewline
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
                    Write-Host "[MAIN]: " -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Uploading script to container...." -NoNewline
                    Set-AzStorageBlobContent -Container "scripts" -File $env:TEMP\RDS-Role.ps1 -Blob "RDS-Role.ps1" -Context $StorageContext -force | out-null
                    Write-Host "Done" -Foregroundcolor Green

                    #Add custom script to VM
                    #=======================
                    Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Adding custom extension...." -NoNewline
                    Set-AzVMCustomScriptExtension -ResourceGroupName $ResourceGroupName -VMName $VMName -Name "$($labPrefix)-Roles" -Location $Location -StorageAccountName $STORAGE.Name -StorageAccountKey $Key -FileName "RDS-Role.ps1" -Run "RDS-Role.ps1" -ContainerName "scripts" | out-null
                    Write-Host "Done" -ForegroundColor Green

                    #Add Role Tag
                    #============
                    Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Adding VM Role Tag...." -NoNewline
                    Set-AzResource -ResourceGroupName $ResourceGroupName -ResourceType Microsoft.Compute/virtualMachines -ResourceName $VMName -Tag @{ "Role"="CloudIDLab_RDS" } -Force | Out-Null
                    Write-Host "Done" -ForegroundColor Green  
                    }
                    if (($VMName -like "*SP*") -and ($Offer -eq "MicrosoftSharePointServer") -and ($SKU -eq "2016") -or ($SKu -eq "2013")) {
                    #Create Roles and Features script
                    #================================
                    Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Provisioning roles and features...." -NoNewline
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
                    Write-Host "[MAIN]: " -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Uploading script to container...." -NoNewline
                    Set-AzStorageBlobContent -Container "scripts" -File $env:TEMP\SP-Role.ps1 -Blob "SP-Role.ps1" -Context $StorageContext -force | out-null
                    Write-Host "Done" -Foregroundcolor Green

                    #Add custom script to VM
                    #=======================
                    Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Adding custom extension...." -NoNewline
                    Set-AzVMCustomScriptExtension -ResourceGroupName $ResourceGroupName -VMName $VMName -Name "$($labPrefix)-Roles" -Location $Location -StorageAccountName $STORAGE.Name -StorageAccountKey $Key -FileName "SP-Role.ps1" -Run "SP-Role.ps1" -ContainerName "scripts" | out-null
                    Write-Host "Done" -ForegroundColor Green
                    
                    #Add Role Tag
                    #============
                    Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Adding VM Role Tag...." -NoNewline
                    Set-AzResource -ResourceGroupName $ResourceGroupName -ResourceType Microsoft.Compute/virtualMachines -ResourceName $VMName -Tag @{ "Role"="CloudIDLab_SP" } -Force | Out-Null
                    Write-Host "Done" -ForegroundColor Green  
                    }
                    elseif ($VMName -like "*EXCH*") {
                    
                    #Create Roles and Features script
                    #================================
                    Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Provisioning roles and features...." -NoNewline
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
                    Write-Host "[MAIN]: " -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Uploading script to container...." -NoNewline
                    Set-AzStorageBlobContent -Container "scripts" -File $env:TEMP\EXCH-Role.ps1 -Blob "EXCH-Role.ps1" -Context $StorageContext -force | out-null
                    Write-Host "Done" -Foregroundcolor Green

                    #Add custom script to VM
                    #=======================
                    Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Adding custom extension...." -NoNewline
                    Set-AzVMCustomScriptExtension -ResourceGroupName $ResourceGroupName -VMName $VMName -Name "$($labPrefix)-Roles" -Location $Location -StorageAccountName $STORAGE.Name -StorageAccountKey $Key -FileName "EXCH-Role.ps1" -Run "EXCH-Role.ps1" -ContainerName "scripts" | out-null
                    Write-Host "Done" -ForegroundColor Green
                    
                    #Add Role Tag
                    #============
                    Write-Host "[CREATEVM]: " -ForegroundColor Yellow -NoNewline
                    Write-Host "$VMName" -ForegroundColor Cyan -NoNewline
                    Write-Host " - Adding VM Role Tag...." -NoNewline
                    Set-AzResource -ResourceGroupName $ResourceGroupName -ResourceType Microsoft.Compute/virtualMachines -ResourceName $VMName -Tag @{ "Role"="CloudIDLab_EXCH" } -Force | Out-Null
                    Write-Host "Done" -ForegroundColor Green  
                    }
}  else {
         Write-Host "already exists. Moving on" -ForegroundColor DarkGray
        }
}

if([string]::IsNullOrEmpty($ForestCreds.UserName)) {
    $ForestCreds = Get-Credential -Message "Enter credentials to be used as the $($ADForestName) domain administrator account. Note - The username cannot contain the string 'Administrator and the password must meet standard complexity requirements"
    $Credentials = Get-Credential -Message "Enter credentials to be used as the VM's local admin account. Note - The username cannot contain the string 'Administrator and the password must meet standard complexity requirements"
}

#Geo picker & resourcegroup mapper
#=================================
$ResourceGroupName = $ResourceGroupOwner + "-" + $labPrefix + "-RG"
Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
Write-Host " - Resource group " -NoNewline
Write-Host "[" -NoNewline
Write-Host "$($ResourceGroupName)" -NoNewline -ForegroundColor Green
Write-Host "] " -NoNewline
Get-AzResourceGroup -Name $ResourceGroupName -ev notPresent -ea 0 | Out-Null
if ($notPresent) { 
        Write-Host "Not found. " -NoNewline
        Write-Host "Select target geo from list" -ForegroundColor cyan
    Try
    {       
	    $Geos = Get-AzLocation | ? {$_.Providers -like '*Automation*' }
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
        $formShowmenu.ShowDialog() | out-null
        $Location = $var1

        Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
        write-host " - Targeted deployment geo [" -NoNewline
        Write-Host "$($var1)" -NoNewline -ForegroundColor Green
        Write-Host "]"
    }
        Catch{
        Write-Host "`nNo geo locations found. Exiting`n" -ForegroundColor Red
        exit
    }
    $formShowmenu.Dispose()
    $RG = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -WA 0
}
else {
    Write-Host "already exists. Moving on" -ForegroundColor DarkGray
    $RG = get-AzResourceGroup -Name $ResourceGroupName -WA 0
    $Location = $RG.Location
    Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
    Write-Host " - Targeted deployment geo....[" -NoNewline
    Write-Host "$Location" -NoNewline -ForegroundColor Green
    Write-Host "]"
}

#Create Shared Storage Account
#=============================
$Random = ( -join ((0x30..0x39) + ( 0x41..0x5A) + ( 0x61..0x7A) | Get-Random -Count 4  | % {[char]$_})).ToLower()
if($Storage = Get-AzResource -ResourceGroupName $resourceGroupName -Tag @{ "Role"="CloudIDLab_StorageAccount" } -ErrorAction SilentlyContinue)
    {  
         if ($Storage.Count -gt 1) { 
            $Storage = $Storage[0]
            Write-Host "[MAIN]: - " -ForegroundColor Yellow -NoNewline 
            Write-Host "Multiple shared storage accounts detected. " -ForegroundColor cyan -NoNewline
            Write-Host "Selecting the first.... " -ForegroundColor white -NoNewline
            Write-Host "[" -NoNewline -ForegroundColor White
            Write-Host "$($STORAGE.Name)" -NoNewline -ForegroundColor Green
            Write-Host "]" -ForegroundColor White -NoNewline
         }
         else {
            Write-Host "[MAIN]: - " -ForegroundColor Yellow -NoNewline
            Write-Host "Shared Storage account " -NoNewline -ForegroundColor white
            Write-Host "[" -NoNewline
            Write-Host "$($STORAGE.Name)" -NoNewline -ForegroundColor Green
            Write-Host "] " -ForegroundColor White -NoNewline
            Write-Host "already exists. Moving on..." -ForegroundColor DarkGray
         }
    }  
else  
    {          
         Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline 
         Write-Host " - Creating shared storage account...." -ForegroundColor white -NoNewline
         if (-not (Get-AzStorageAccountNameAvailability -Name "$($labPrefix)storage" -WA 0)) {
            Write-Host "[" -NoNewline -ForegroundColor White
            Write-Host "$($labPrefix.ToLower())storage" -NoNewline -ForegroundColor Green
            Write-Host "]" -ForegroundColor White
            New-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name "$($labPrefix.ToLower())storage" -Location $Location -SkuName Standard_LRS -Kind Storage -Tag @{ "Role"="CloudIDLab_StorageAccount" } | out-null
            do {
                sleep -seconds 1
                $Storage = Get-AzResource -ResourceGroupName $resourceGroupName -Tag @{ "Role"="CloudIDLab_StorageAccount" } -ErrorAction SilentlyContinue
                } while (!$Storage)
         }
         else {
            Write-Host "[" -NoNewline -ForegroundColor White
            Write-Host "$($labPrefix.ToLower())storage$($Random)" -NoNewline -ForegroundColor Green
            Write-Host "]" -ForegroundColor White
            New-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name "$($labPrefix.ToLower())storage$($Random)" -Location $Location -SkuName Standard_LRS -Kind Storage -tag @{ "Role"="CloudIDLab_StorageAccount" } | out-null
            do {
                sleep -seconds 1
                $Storage = Get-AzResource -ResourceGroupName $resourceGroupName -Tag @{ "Role"="CloudIDLab_StorageAccount" } -ErrorAction SilentlyContinue
                } while (!$Storage)
         }
    }

#Create BLOB Storage Container to host scripts
#=============================================
Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
Write-Host " - Creating " -NoNewline
Write-Host "[" -NoNewline -ForegroundColor White
Write-Host "Scripts" -NoNewline -ForegroundColor Green
Write-Host "] " -ForegroundColor White -NoNewline
Write-Host "container...." -NoNewline
$Key = (Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $STORAGE.Name  -WA 0).Value[0]
$StorageContext = New-AzStorageContext -StorageAccountName $STORAGE.Name -StorageAccountKey $Key
if(Get-AzStorageContainer -Context $StorageContext | ? {$_.name -eq "scripts"}) {
        Write-Host "already exists. Moving on" -ForegroundColor DarkGray
}   else {
        New-AzStorageContainer -Name "scripts" -Context $StorageContext -WA 0 | Out-Null
        Write-Host "Done" -ForegroundColor Green
        }

#Create Automation Account to hold runbooks/dsc configs
#======================================================
Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
Write-Host " - Creating Automation Account...." -NoNewline
Write-Host "[" -NoNewline -ForegroundColor White
Write-Host "Internal" -NoNewline -ForegroundColor Green
Write-Host "]" -ForegroundColor White -NoNewline
Write-Host "...." -NoNewline
if(-not (Get-AzResource -ResourceGroupName $ResourceGroupName -ResourceType "Microsoft.Automation/automationAccounts" -Name "$($labPrefix)-Automation" -Tag @{ "Role"="CloudIDLab_AutomationAccount" } -EA SilentlyContinue)) {
    Try {    
        $AUTOACC = New-AzAutomationAccount -ResourceGroupName $ResourceGroupName -Name "$($labPrefix)-Automation" -Location $Location -Tag @{ "Role"="CloudIDLab_AutomationAccount" } -WA 0
        Write-Host "Done" -ForegroundColor Green
  } catch {
        $ErrorMessage = $_.Exception.Message
        $FailedItem = $_.Exception.ItemName
        Write-Host "Unable to create automation account" -ForegroundColor DarkGray
        Break
        } 
}
else {
    $AUTOACC = get-AzAutomationAccount -ResourceGroupName $ResourceGroupName -Name "$($labPrefix)-Automation" -WA 0
    Write-Host "$($AUTOACC.AutomationAccountName) already exists. Moving on" -ForegroundColor DarkGray
}

#Create Int VNET Rule to allow RDP to all VMs
#============================================
Write-Host "[TRAFFIC]:" -ForegroundColor Yellow -NoNewline
Write-Host " - Generating Internal VNET Ruleset...." -NoNewline
$arrVNETRulesInt = @()
$INTVNETSR = New-AzNetworkSecurityRuleConfig -WA 0 `
    -Name "allow-rdp-access" `
    -Description "Allow RDP Access to VMs" `
    -Protocol Tcp -SourcePortRange * `
    -DestinationPortRange 3389 `
    -SourceAddressPrefix * `
    -DestinationAddressPrefix * `
    -Access Allow -Priority 100 `
    -Direction Inbound
$arrVNETRulesInt += $INTVNETSR
Write-Host "[" -NoNewline
Write-Host "RDP to VMs" -NoNewline -ForegroundColor Green
Write-Host "]" -ForegroundColor White

#Create Int VNET Rule to allow 443 to WAP
#========================================
Write-Host "[TRAFFIC]:" -ForegroundColor Yellow -NoNewline
Write-Host " - Generating Internal VNET Ruleset...." -NoNewline
$INTVNETSR1 = New-AzNetworkSecurityRuleConfig -WA 0 `
    -Name "allow-https-access" `
    -Description "Allow 443 to WAP" `
    -Protocol Tcp -SourcePortRange * `
    -DestinationPortRange 443 `
    -SourceAddressPrefix * `
    -DestinationAddressPrefix * `
    -Access Allow -Priority 101 `
    -Direction Inbound
$arrVNETRulesInt += $INTVNETSR1
Write-Host "[" -NoNewline
Write-Host "443 to WAP" -NoNewline -ForegroundColor Green
Write-Host "]" -ForegroundColor White

#Create Int VNET Rule to allow 49443 to WAP
#========================================
Write-Host "[TRAFFIC]:" -ForegroundColor Yellow -NoNewline
Write-Host " - Generating Internal VNET Ruleset...." -NoNewline
$INTVNETSR2 = New-AzNetworkSecurityRuleConfig -WA 0 `
    -Name "allow-clientcertauth-access" `
    -Description "Allow 49443 to WAP" `
    -Protocol Tcp -SourcePortRange * `
    -DestinationPortRange 49443 `
    -SourceAddressPrefix * `
    -DestinationAddressPrefix * `
    -Access Allow -Priority 102 `
    -Direction Inbound
$arrVNETRulesInt += $INTVNETSR2
Write-Host "[" -NoNewline
Write-Host "49443 to WAP" -NoNewline -ForegroundColor Green
Write-Host "]" -ForegroundColor White


#Create VNET Security Group
#==========================
Write-Host "[TRAFFIC]:" -ForegroundColor Yellow -NoNewline
Write-Host " - Creating Network Security Group (NSG) & Rules...." -NoNewline
if(-Not (Get-AzResource -ResourceGroupName $ResourceGroupName -ResourceType "Microsoft.Network/networkSecurityGroups" -Name "$($labPrefix)-Int-NSG" -ErrorAction SilentlyContinue)) {
	$INTVNETSG = New-AzNetworkSecurityGroup -WA 0 `
	-Name "$($labPrefix)-Int-NSG" `
	-ResourceGroupName $ResourceGroupName `
	-Location $Location `
	-SecurityRules $arrVNETRulesInt `
	-Force
	Write-Host "Done" -ForegroundColor Green
}
else {
	Write-Host "NSG already exists. Moving on" -ForegroundColor DarkGray
    $INTVNETSG = Get-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName -Name "$($labPrefix)-Int-NSG"
}

#Create VNET & Subnet 
#====================
Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
Write-Host " - Generating VNet and " -NoNewline
Write-Host "[" -NoNewline -ForegroundColor White
Write-Host "Internal" -NoNewline -ForegroundColor Green
Write-Host "] " -ForegroundColor White -NoNewline
Write-Host "Subnet...." -NoNewline
if(-Not (Get-AzVirtualNetwork -Name "$($labPrefix)-VNET" -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue)) {
        $VNETIntSUBNET = New-AzVirtualNetworkSubnetConfig -Name "$($labPrefix)-Internal" -AddressPrefix $LANSubnetIPBlock -NetworkSecurityGroup $INTVNETSG
        $LanSubnetIPBlock,$LANSubnetCIDR = $LanSubnetIPBlock.Split("/")    
        $VNET = New-AzVirtualNetwork -Name "$($labPrefix)-VNET" -ResourceGroupName $ResourceGroupName -Location $Location -AddressPrefix $VNetIPBlock -Tag @{ "Role"="CloudIDLab_VNet" } -DnsServer @($($LANSubnetIPBlock -replace '(.*)\.\d+$',"`$1.50"), '8.8.4.4') -Subnet $VNETIntSUBNET -Force
		Write-Host "Done" -ForegroundColor Green		
}
else {
		Write-Host "already exists. Moving on..." -ForegroundColor DarkGray
        $VNET = Get-AzVirtualNetwork -Name "$($labPrefix)-VNET" -ResourceGroupName $ResourceGroupName -WA 0
}
$VNETSubID = (Get-AzVirtualNetworkSubnetConfig -VirtualNetwork $VNET -Name "Internal").Id

# Generate mRemoteNG download link and VM file
#===============================================================
function Get-AzureVmEndpoint
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
            Get-AzVm -ResourceGroupName $ResourceGroupName |  
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
 
                Get-AzRemoteDesktopFile -ResourceGroupName $ResourceGroupName -Name $rgvm -LocalPath $tempFile -ErrorAction SilentlyContinue 
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

    Remove-Item -Path $tempFile -ErrorAction SilentlyContinue
}

function New-AzureVmRdg 
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
 
    $azureVm = Get-AzVm -ResourceGroupName $ResourceGroupName

    if (!$Path) { $Path = "$home\Desktop\AzureRDG\Azure-$($labPrefix)-VMs.rdg" }  
 
    if (!(Test-Path -Path $Path)) { New-Item -Path $Path -ItemType File -Force } 
 
    $Path = Convert-path -Path $Path 
 
    $rdgXml = New-RdgXml -FileElementName $ResourceGroupName 
    $rootFileNode = $rdgXml.RDCMan.file 
 
        $groupXmlElement = $rdgXml.CreateElement('group') 
 
        $groupXmlElement.InnerXml = Get-RdgGroupInnerXml -GroupElementName $ResourceGroupName 
        $null = $rootFileNode.AppendChild($groupXmlElement) 
 
        $vmObjects =  $azureVm | 
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


############################################ VM NAME, IP, Size, and SKU, are defined below. Add VMs as necessary ######################################
################################################################ Only chnage the last octect, #########################################################
###################### VM NAMES ARE BEST UNIQUE ACCROSS AZURE REGION AS WOULD ALLOW YOU TO USE DNS FOR RDP INSTEAD PUBLIC IP ##########################
## Host name (VMName) should contain role, so that script logic can apply function specific additions. E.g. MFA server will only be provisioned with MFAServer.exe package if "mfa" is in hostname. Same for RDS, etc. 


# Call nGRemote function
Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
Write-Host " RDP to VMs " -ForegroundColor Cyan -NoNewline
Write-Host " - Generating VM collection for nGRemote Desktop Manager...." -NoNewline
New-AzureVmRdg $ResourceGroupName -WA 0 | Out-Null
Write-Host "Done`n" -ForegroundColor Green

# Job done, closing out...
$wshell = New-Object -ComObject Wscript.Shell
$wshell.Popup(" Go ahead and install mRemoteNG and import the pre-generated Azure-$($labPrefix)-VMs.rdg VM collection file",0," Job complete...",0x0) | Out-Null
invoke-item "$home\Desktop\AzureRDG\"

## Disconnect from Azure Account
Write-Host "[MAIN]:" -ForegroundColor Yellow -NoNewline
Write-Host " Disconnecting from Azure...." -ForegroundColor white -NoNewline
Disconnect-AzAccount | Out-Null
Write-Host "Done`n" -ForegroundColor Green
