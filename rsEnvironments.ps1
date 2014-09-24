##################################################################################################################################
##################################################################################################################################
#This script configures the Pull server
#This script is called by baseprep.ps1 during the automated workflow and continues to run with Verify Task
##################################################################################################################################
##################################################################################################################################



##################################################################################################################################
# Import RS Cloud and Github account information.
##################################################################################################################################
. "C:\cloud-automation\secrets.ps1"


##################################################################################################################################
# Begin Configuration
##################################################################################################################################
configuration Assert_DSCService
{
   param
   (
      [string[]]$NodeName,
      [ValidateNotNullOrEmpty()]
      [string] $certificateThumbPrint
   )
   
   
   ##################################################################################################################################
   # Import Required Modules
   ##################################################################################################################################
   Import-DscResource -ModuleName rsCloudServersOpenStack
   Import-DscResource -ModuleName rsCloudLoadBalancers
   Import-DscResource -ModuleName rsScheduledTask
   Import-DscResource -ModuleName msPSDesiredStateConfiguration
   Import-DscResource -ModuleName rsPlatform
   Import-DscResource -ModuleName rsGit
   Import-DscResource -ModuleName rsClientMofs
   Import-DSCResource -ModuleName msWebAdministration
   Import-DSCResource -ModuleName PowerShellAccessControl
   Import-DSCResource -ModuleName msNetworking
   
   Node $NodeName
   {
    
      ##################################################################################################################################
      # Install Required Windows Features (pull server)
      ##################################################################################################################################
      WindowsFeature IIS
      {
         Ensure = "Present"
         Name = "Web-Server"
      }
      
      WindowsFeature InetMgr
      {
         Ensure = "Present"
         Name = "Web-Mgmt-Tools"
      }
      
      WindowsFeature DSCServiceFeature
      {
         Ensure = "Present"
         Name = "DSC-Service"
      }
      
      
      ##################################################################################################################################
      # Install DSC Webservices
      ##################################################################################################################################
      
      xDscWebService PSDSCPullServer
      {
         Ensure = "Present"
         EndpointName = "PSDSCPullServer"
         Port = 8080
         PhysicalPath = "$env:SystemDrive\inetpub\wwwroot\PSDSCPullServer"
         CertificateThumbPrint = $certificateThumbPrint
         ModulePath = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Modules"
         ConfigurationPath = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Configuration"
         State = "Started"
         DependsOn = "[WindowsFeature]DSCServiceFeature"
      }
      
      xDscWebService PSDSCComplianceServer
      {
         Ensure = "Present"
         EndpointName = "PSDSCComplianceServer"
         Port = 9080
         PhysicalPath = "$env:SystemDrive\inetpub\wwwroot\PSDSCComplianceServer"
         CertificateThumbPrint = $certificateThumbPrint
         State = "Started"
         IsComplianceServer = $true
         DependsOn = @("[WindowsFeature]DSCServiceFeature","[xDSCWebService]PSDSCPullServer")
      }
      
      
      ##################################################################################################################################
      # Pull Down Modules that are setup in rsPlatform
      ##################################################################################################################################
      
      rsGit rsConfigs
      {
         name = "rsConfigs"
         Source = (("git@github.com:", $($d.gCA) -join ''), $($($d.mR), ".git" -join '') -join '/')
         Destination = $($d.wD)
         Ensure = "Present"
         Branch = "master"
         Logging = $false
      }
      
      File rsPlatformDir
      {
         SourcePath = $($d.wD, $d.mR, "rsPlatform" -join '\')
         DestinationPath = "C:\Program Files\WindowsPowerShell\Modules\rsPlatform"
         Type = "Directory"
         Recurse = $true
         Ensure = "Present"
      }
      
      rsPlatform Modules
      {
         Ensure = "Present"
      }

      ##################################################################################################################################
      # Define server and loadbalancer environments (Orchestration Layer)
      ##################################################################################################################################
      
      ### Environment section commented out for template, please edit this section for your own environment builds
      
<#
      rsCloudServersOpenStack DFWwebfarm
      {
        Ensure = "Present"
        minNumberOfDevices = 1
        maxNumberOfDevices = 9
        namingConvention = "Farm"
        image = "Windows Server 2012"
        nflavor = "performance1-4"
        dataCenter = "DFW"
        role = "webFarm"
        pullServerName = "PULLServer"
        environmentGuid = "UNIQUEGUID"
        BuildTimeOut = 30
        EnvironmentName = "DFWwebfarm"
      }


      rsCloudServersOpenStack DFWDevfarm
      {
        Ensure = "Absent"
        minNumberOfDevices = 1
        maxNumberOfDevices = 9
        namingConvention = "DevFarm"
        image = "Windows Server 2012"
        nflavor = "performance1-4"
        dataCenter = "DFW"
        role = "webFarm"
        pullServerName = "PULLServer"
        environmentGuid = "UNIQUEGUID"
        BuildTimeOut = 30
        EnvironmentName = "DFWDevfarm"
      }


      rsCloudLoadBalancers prod_dfwlb
      {
        loadBalancerName = "dfwlb"
        port = 80
        protocol = "HTTP"
        nodes = @("ENVIRONMENTGUIDTOBEUSED")
        dataCenter = "DFW"
        attemptsBeforeDeactivation = 3
        delay = 10
        path = "/"
        hostHeader = "windevops.local"
        statusRegex = "^[234][0-9][0-9]$"
        timeout = 10
        type = "HTTP"
        algorithm = "ROUND_ROBIN"
      }
#>      
      
      ##################################################################################################################################
      # Add Github SSH keys to known hosts and add pull server SSH key to github account - Add Github webhook
      ##################################################################################################################################
      rsClientMofs CheckMofs
      {
         Name = "CheckMofs"
         Ensure = "Present"
         Logging = $true
      }
      
      rsSSHKnownHosts gitssh
      {
         path = "C:\Program Files (x86)\Git\.ssh"
         gitIps = @("github.com,192.30.252.129", "192.30.252.128", "192.30.252.130", "192.30.252.131")
         gitRsa = "AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ=="
      }
      
      rsSSHKnownHosts systemprofile
      {
         path = "C:\Windows\System32\config\systemprofile\.ssh"
         gitIps = @("github.com,192.30.252.129", "192.30.252.128", "192.30.252.130", "192.30.252.131")
         gitRsa = "AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ=="
      }
      
      rsSSHKnownHosts adminprofile
      {
         path = "C:\Users\Administrator\.ssh"
         gitIps = @("github.com,192.30.252.129", "192.30.252.128", "192.30.252.130", "192.30.252.131")
         gitRsa = "AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ=="
      }
      
      rsSSHKnownHosts syswow
      {
         path = "C:\Windows\SysWOW64\config\systemprofile\.ssh"
         gitIps = @("github.com,192.30.252.129", "192.30.252.128", "192.30.252.130", "192.30.252.131")
         gitRsa = "AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ=="
      }
      
      rsGitSSHKey pullserver_sshkey
      {
         installedPath = "C:\Program Files (x86)\Git\.ssh"
         hostedPath = $(($d.wD), $($d.mR), "Certificates" -join '\') 
         logging = $false
      }
      
      rsGit GitDeployHub
      {
         name = "GitDeployHub"
         Source = $("https://github.com", $($d.gMO), ("gitdeployhub.git" -join '') -join '/')
         Destination = "C:\inetpub\wwwroot\"
         Ensure = "Present"
         Branch = "master"
      }
      
      xWebAppPool GitDeployHub
      {
         Name = "GitDeployHub"
         Ensure = "Present"
         State = "Started"
      }
      
      xWebSite GitDeployHub
      {
         Name = "GitDeployHub"
         ApplicationPool = "GitDeployHub"
         Ensure = "Present"
         State = "Started"
         PhysicalPath = "$env:SystemDrive\inetpub\wwwroot\gitdeployhub\web\"
         BindingInfo = @(
            @(MSFT_xWebBindingInformation
            {
                IPAddress = "*"
                Port = 9110
                Protocol = "HTTP"
            });
         )
         DependsOn = @("[xWebAppPool]GitDeployHub")
      }
      
      cAccessControlEntry ModifyGitDeployHub
      {
         Ensure = "Present"
         Path = "$env:SystemDrive\inetpub\wwwroot\gitdeployhub\"
         AceType = "AccessAllowed"
         ObjectType = "Directory"
         AccessMask = ([System.Security.AccessControl.FileSystemRights]::Modify)
         Principal = "IIS AppPool\GitDeployHub"
         DependsOn = "[rsGit]GitDeployHub"
      }



# GitDeployHub
      rsWebHook DDI_rsConfigs
      {
         Name = "DDI_rsConfigs"
         Repo = "$($d.mR)"
         PayloadURL = $( "http://",$($pullserverInfo.pullserverPublicIp),":9110/Deployment/SmokeTest/_self?source=DDI_rsConfigs" -join'' )
         Ensure = "Present"
         Logging = $true
      } 

<#
# Arnie - not in use yet - leave commented
      rsWebHook DDI_rsConfigs
      {
         Name = "DDI_rsConfigs"
         Repo = "$($d.mR)"
         PayloadURL = $( "http://",$($pullserverInfo.pullserverPublicIp),"/API/Arnie.svc/DoItNow" -join'' )
         Ensure = "Present"
         Logging = $true
      } 
#>
      
      xFirewall Firewall
      {
         Name = "GitDeployHub"
         DisplayName = "Allow Port 9110 for GitDeployHub"
         Ensure = "Present"
         Access = "Allow"
         State = "Enabled"
         Profile = ("Any")
         Direction = "InBound"
         LocalPort = ("9110")
         Protocol = "TCP"
      }
      
      
      ##################################################################################################################################
      # Create scheduled task to verify config - executed by Github Webhook & on its own scheduled interval
      ##################################################################################################################################
      rsScheduledTask VerifyTask
      {
         ExecutablePath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
         Params = $($d.wD, $d.prov, "Verify.ps1" -join '\')
         Name = "Verify"
         IntervalModifier = "Minute"
         Ensure = "Present"
         Interval = "30"
      }
      
      cAccessControlEntry ReadExecuteVerify
      {
         Ensure = "Present"
         Path = "C:\Windows\System32\Tasks\Verify"
         AceType = "AccessAllowed"
         ObjectType = "File"
         AccessMask = ([System.Security.AccessControl.FileSystemRights]::ReadAndExecute)
         Principal = "IIS AppPool\GitDeployHub"
         DependsOn = "[rsScheduledTask]VerifyTask"
      }
   }
   
}
##################################################################################################################################
# Configuration end - lines below run the config and create/install cert used for client/pull HTTPS comms
##################################################################################################################################
taskkill /F /IM WmiPrvSE.exe
$NodeName = $env:COMPUTERNAME
$cN = "CN=" + $NodeName
Remove-Item -Path "C:\Windows\Temp\Assert_DSCService" -Force -Recurse -ErrorAction SilentlyContinue
if(!(Get-ChildItem Cert:\LocalMachine\My\ | where {$_.Subject -eq $cN}) -or !(Get-ChildItem Cert:\LocalMachine\Root\ | where {$_.Subject -eq $cN})) {
   Get-ChildItem Cert:\LocalMachine\My\ | where {$_.Subject -eq $cN} | Remove-Item
   Get-ChildItem Cert:\LocalMachine\Root\ | where {$_.Subject -eq $cN} | Remove-Item
   if(!(Test-Path -Path $($d.wD, $d.mR, "Certificates" -join '\'))) {
      New-Item -Path $($d.wD, $d.mR, "Certificates" -join '\') -ItemType directory
   }
   if($($d.wD, $d.mR, "Certificates\PullServer.cert.pfx" -join '\')) {
      Remove-Item -Path $($d.wD, $d.mR, "Certificates\PullServer.cert.pfx" -join '\') -Force
   }
   powershell.exe $($d.wD, $d.prov, "makecert.exe" -join '\') -r -pe -n $cN, -ss my $($d.wD, $d.mR, "Certificates\PullServer.cert.pfx" -join '\'), -sr localmachine, -len 2048
   chdir $($d.wD, $d.mR -join '\')
   Start-Service Browser
   Start -Wait "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "add $($d.wD, $d.mR, "Certificates/PullServer.cert.pfx" -join '\')"
   Start -Wait "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "commit -a -m `"pushing PullServer.cert.pfx`""
   Start -Wait "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "pull origin $($d.br)"
   Start -Wait "C:\Program Files (x86)\Git\bin\git.exe" -ArgumentList "push origin $($d.br)"
   Stop-Service Browser
   powershell.exe certutil -addstore -f my $($d.wD, $d.mR, "Certificates\PullServer.cert.pfx" -join '\')
   powershell.exe certutil -addstore -f root $($d.wD, $d.mR, "Certificates\PullServer.cert.pfx" -join '\')
}
chdir C:\Windows\Temp
Assert_DSCService -NodeName $NodeName -certificateThumbPrint (Get-ChildItem Cert:\LocalMachine\My\ | where {$_.Subject -eq $cN}).Thumbprint
Start-DscConfiguration -Path Assert_DSCService -Wait -Verbose -Force
