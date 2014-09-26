﻿#This is script is used to prepare the test client server to install IIS and Inetmgr
#This script is built into the automation workflow
param ([string]$Node, [string]$ObjectGuid, [string]$MonitoringID, [string]$MonitoringToken)

. "C:\cloud-automation\secrets.ps1"

##################################################################################################################################
# Import RS Cloud and Github account information.
##################################################################################################################################

$CfgData = @{
    AllNodes = @(
        @{
            NodeName = $node
            PSDscAllowPlainTextPassword = $true
         }
   )
}

Configuration Nodes
{
   Import-DSCResource -ModuleName rsScheduledTask
   Import-DSCResource -ModuleName rsGit
   Import-DSCResource -ModuleName msWebAdministration
   
   Node $Node
   {       
      WindowsFeature IIS
      {
         Ensure = "Present"
         Name = "Web-Server"
      }
      WindowsFeature WebManagement
      {
         Ensure = "Present"
         Name = "Web-Mgmt-Tools"
      }
      WindowsFeature AspNet45
      {
         Ensure          = "Present"
         Name            = "Web-Asp-Net45"
      }
      rsGit rsConfigs
      {
         Name            = "rsConfigs"
         Ensure          = "Present"
         Source          =  $(("git@github.com:", $($d.gCA) -join ''),  $($($d.mR), ".git" -join '') -join '/')
         Destination     = $($d.wD)
         Branch          = "master"
      }
      rsGit rsProvisioning
      {
         Name            = "rsProvisioning"
         Ensure          = "Present"
         Source          = $("https://github.com", $($d.gMO) , $($($d.prov), ".git" -join '' ) -join '/')
         Destination     = $($d.wD)
         Branch          = "master"
      }
      xWebsite DefaultSite 
      {
         Ensure          = "Present"
         Name            = "Default Web Site"
         State           = "Stopped"
         PhysicalPath    = "C:\inetpub\wwwroot"
         DependsOn       = "[WindowsFeature]IIS"
      }

      xWebAppPool ABAppPool 
      { 
         Name   = "ABBlog" 
         Ensure = "Present" 
         State  = "Started" 
      }
      xWebSite WinDevOps
      { 
         Name   = "WinDevOps" 
         Ensure = "Present" 
         ApplicationPool = "ABBlog"
         BindingInfo = MSFT_xWebBindingInformation 
         { 
            Port = 80
            Protocol = "HTTP"
            HostName = "ABWinDevOps.local"
         }
         PhysicalPath = "D:\WebSites\ABWinDevOps"
         State = "Started" 
         DependsOn = @("[xWebAppPool]ABAppPool","[file]WebPath","[file]indexfile") 
      }
      File WebPath 
         {
         Ensure          = "Present" 
         DestinationPath = "D:\WebSites\ABWinDevOps" 
         Type            = "Directory" 
         }
      File indexfile
        {
        Ensure = "Present"
        DestinationPath = "D:\WebSites\ABWinDevOps\index.html"
        Contents = "Hello World"
        Type = "File"
        DependsOn = @("[File]WebPath")
        }

    $PScred_abounds = New-Object System.Management.Automation.PSCredential ("abounds", (ConvertTo-SecureString "Thesteh8sas#4+e8" -AsPlainText -Force))
    $PScred_testuser = New-Object System.Management.Automation.PSCredential ("testuser", (ConvertTo-SecureString "Thetest7shd#5-c3" -AsPlainText -Force))
    
    User abounds
        {
        UserName = $PScred_abounds.UserName
        Description = "Test abounds"
        Disabled = $false
        Ensure = "Present"
        FullName = "Alan Bounds"
        Password = $PScred_abounds
        PasswordNeverExpires = $True
        }
    User testuser
        {
        UserName = $PScred_testuser.UserName
        Description = "Test User"
        Disabled = $true
        Ensure = "Present"
        FullName = "Test User"
        Password = $PScred_testuser
        PasswordNeverExpires = $False
        }

    Group Admins
        {
        Ensure = "Present"
        GroupName = "Admins"
        MembersToInclude = @("abounds")
        DependsOn = @("[user]abounds")
        }

    Group Administrators
        {
        Ensure = "Present"
        GroupName = "Administrators"
        MembersToInclude = @("Admins","Administrator","testuser")
        }
    
   <#
      xWebAppPool WebBlogAppPool 
      { 
         Name   = "WebBlog" 
         Ensure = "Present" 
         State  = "Started" 
      }
      xWebAppPool WinDevOpsAppPool
      { 
         Name   = "WinDevOps" 
         Ensure = "Present" 
         State  = "Started" 
      }
      rsGit WebSites
      {
         Name            = "WebSites"
         Ensure          = "Present"
         Source          = "git@github.com:<customergithubaccount>/WebSites.git"
         Destination     = "D:\"  
         Branch          = "master"
      }
      
      xWebSite WinDevOps
      { 
         Name   = "WinDevOps" 
         Ensure = "Present" 
         ApplicationPool = "WinDevOps"
         BindingInfo = MSFT_xWebBindingInformation 
         { 
            Port = 80
            Protocol = "HTTP"
            HostName = "WinDevOps.local"
         }
         PhysicalPath = "D:\WebSites\WinDevOps"
         State = "Started" 
         DependsOn = @("[xWebAppPool]WinDevOpsAppPool","[rsGit]WebSites") 
      } 
      xWebSite WebBlog
      { 
         Name   = "WebBlog" 
         Ensure = "Present" 
         ApplicationPool = "WebBlog"
         BindingInfo = MSFT_xWebBindingInformation 
         { 
            Port = 80
            Protocol = "HTTP"
            HostName = "webblog.local"
         }
         PhysicalPath = "D:\WebSites\WebBlog"
         State = "Started" 
         DependsOn = @("[xWebAppPool]WebBlogAppPool","[rsGit]WebSites") 
      } 
      #>
      rsScheduledTask VerifyTask
      {
         ExecutablePath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
         Params = $($d.wD, $d.prov, "Verify.ps1" -join '\')
         Name = "Verify"
         IntervalModifier = "Minute"
         Ensure = "Present"
         Interval = "5"
      }
   }
}
$fileName = [System.String]::Concat($ObjectGuid, ".mof")
$mofFile = Nodes -ConfigurationData $CfgData -Node $Node -ObjectGuid $ObjectGuid -OutputPath 'C:\Program Files\WindowsPowerShell\DscService\Configuration\'
$newFile = Rename-Item -Path $mofFile.FullName -NewName $fileName -PassThru
New-DSCCheckSum -ConfigurationPath $newFile.FullName -OutPath 'C:\Program Files\WindowsPowerShell\DscService\Configuration\'