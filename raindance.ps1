<# 
 .Synopsis
  Intelligence Gathering tool for Office 365 & Microsoft Exchange

 .Description
    Authenticate to an O365/MSExchange user to perform intelligence 
    gathering on the domain from the user-context using some snazzy, 
    hopefully user-friendly cmdlets, or via the menu wizard.

 .License
    Copyright (c) 2018, SecureState, LLC
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are
    met:
    
     * Redistributions of source code must retain the above copyright
       notice, this list of conditions and the following disclaimer.
     * Redistributions in binary form must reproduce the above
       copyright notice, this list of conditions and the following disclaimer
       in the documentation and/or other materials provided with the
       distribution.
     * Neither the name of the project nor the names of its
       contributors may be used to endorse or promote products derived from
       this software without specific prior written permission.
    
    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
    A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
    OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
    SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
    LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
    DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
    THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
    OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 .Example
   # Print Help Message & Usage
   Rain-Help

 .Example
   # List available cmdlets
   Rain-Help

#>

function Get-Banner{
    $BANNER= @"


   \ _( )_ \   \           _( )_  \        \  
   _(     )_      _( )_   (     )     \  \    
  (_________) \ _(     )_(_     _)           
    \  \  \    (_________)________)    \ \   \
\     \  \       \  \  \(__________) \     
\             \    \  \  \    \  \ \      \  
     \   .  \      \    \   \    \  \     \   
\ \_O/     \           \ ,      \      \ \  \
     \  \     \    \    /     \     \O_       
     /\_  \           \_\        ,/\/       \
     \          ,    \   \    \    /  \  \     
  ___     \          __ /O\      \ \         \
 |  _ \ __ _(_)_ __ |  _ \  __ _ _ __   ___ ___
 | |_) / _  | | '_ \| | | |/ _  | '_ \ / __/ _ \
 |  _ < (_| | | | | | |_| | (_| | | | | (_|  __/
 |_| \_\__,_|_|_| |_|____/ \__,_|_| |_|\___\___|
             - Office 365 Info-Gathering Toolkit

PRO-TIP: Use 'Rain-help' for a list of commands
UBER PRO-TIP: Rain-Debug will list variables and additional cmdlets for more advanced users
"@

    Write-Output $BANNER
}

function Load-Modules {
    if ($PSVersionTable.PSVersion.Major -lt 5){
        Write-Host("*********************************************")
        Write-Host("[-] Minimum PowerShell Version of 5.0 not met.")
        Exit
    }
    $OS=[System.Environment]::OSVersion.Platform
    if ($OS -like "*nix*"){
        Write-Host("Microsoft currently does not support the necessary libraries (MSOnline & AzureAD) on Linux.  n
        Sorry but you'll have to use Windows... :(")
        Read-Host -Prompt "Press enter to exit..."
        Exit-PSSession
    }

    if (!(Get-Module -ListAvailable -Name MSOnline)){
        Write-Output("This tool requires MSOnline PS-module to be installed. Installing...")
        try {
            Install-Module MSOnline
        }
        catch
        {
            Write-Output("Error, unable to install MSOnline. Try running Powershell as administrator and executing the following...")
            Write-Output("Install-Module PackageManagement -Force")
            Write-Output("Install-Module MSOnline")
            Read-Host -prompt 'Hit "Enter" to exit...'
            Exit-PSSession
        }
    }
    if (!(Get-Module -ListAvailable -Name AzureAD)){
        Write-Output("This tool requires AzureAD PS-Module to be installed. Installing...")
        try {
            Install-Module AzureAD
        }
        catch
        {
            Write-Output("Error, unable to install AzureAD. Try running Powershell as administrator and executing the following...")
            Write-Output("Install-Module AzureAD")
            Read-Host -prompt 'Hit "Enter" to exit...'
            Exit-PSSession
        }
    }
    Import-Module MSOnline
    Import-Module AzureAD
}

function check-import{
    if(!(Get-Module -Name raindance)){
        Write-Host "[!]Do not execute as a script! "
        Write-Host "-> Start this tool with 'Import-Module .\raindance.ps1'"
        Read-Host -prompt "Press enter to continue..."
        Exit-PSSession
    }
}

function Rain-Help{
    $help_text = @"
    --------------_LOG IN_--------------
    [*] Use this command first to begin your magical journey into the land of Office :D

    Rain-Login     | Log into Office365, AzureAD & Exchange
    
    
    -----------_GET COMMANDS_-----------
    [*] These commands gather data and store it in memory to be recalled later by the show commands
     ==> Use the "-verbose" option to return ALL output, including empty/useless stuff
     ==> BE PATIENT! These commands take a while to complete. The more info, the longer it takes.
     ==> Wait a few minutes and hit space if the console appears to hang. It's just thinking ;)

    Rain-GetAll    | Get all user, group, role, & admin information at once (Takes a long time)
    Rain-GetUsers  | Get all user information (MUST BE RUN FIRST)"
    Rain-GetDevices| Get all active devices on the AzureAD Domain with currently logged in sessions
    Rain-GetRoles  | Get all user roles (O365 permissions) details (MUST BE RUN SECOND)
    Rain-GetGroup  | Get all distribution/security group details
    Rain-GetGroupMembers | Get all members of distribution groups (MUST HAVE RUN Rain-GetGroup)
    Rain-GetAdmins | Get all administrative users

    
    -----------_SHOW COMMANDS_-----------
    [*] These commands show the data you've gathered up. Very quick, very clean. :)
    
    Rain-Show <object>     | Show gathered information currently in memory. Options below.
                    |
                    |-> Users
                    |-> Devices
                    |-> Roles
                    |-> Groups
                    |-> GroupMembers
                    |-> Admins
                    |-> GlobalAdmins
    Example: 'Rain-Show Admins' 
    
    -----------_DUMP COMMANDS_------------
    [*] Dump currently gathered information to a csv file(s) or txt file. 
     ==> DumpAll to txt format will dump all information to a SINGLE, formatted file. 
     ==> DumpAll CSV will create 1 csv file per list (user.csv, admins.csv, etc)
    
    Rain-DumpAll <path> <type>        | Dumps all gathered information to csv (default) or txt formatted files. (Files are auto-named)
    Rain-DumpUsers <filepath> <type>  | Dumps all user information to csv (default) or txt formatted files
    Rain-DumpDevices <filepath> <type>| Dumps all gathered device sessions to csv (default) or txt formatted files.
    Rain-DumpRoles <filepath> <type>  | Dumps all role information to csv (default) or txt formatted files
    Rain-DumpAdmins <filepath <type>  | Dumps all administrator (and global admins) to csv (default) or txt formatted files
    Rain-DumpGroups <filepath> <type> | Dumps all security & distribution groups to csv (default) or txt formatted files 

    -----------_OTHER COMMANDS_------------
    [*] Commands that divulge other information about the domain
    Rain-Company   | Get information about the organization along with some policy information (alias for Get-MsolCompanyInformation)
    
"@
    Write-Host $help_text
}

function Rain-Debug{
    $debug_text = @"
        ---------_VARIABLES AVAILABLE_---------
    Feel free to manipulate these variables to get more verbose output once they have been instantiated.
    Please note, these are global variables, and must be re-declared any time values are re-assigned. 

    O_USERS     - Return output of users gathered by Rain-GetUsers
    O_ROLES     - Return output of roles gathered by Rain-GetRoles
    O_GROUPS    - Return output of mailing groups gathered by Rain-GetGroups
    O_ADMINS    - Return output of administrators (not global admin) gathered by Rain-GetAdmins
    O_GADMINS   - Return output of global administrators gathered by Rain-GetAdmins
"@
}

function Rain-Login{
    <#
    .Description
    Log into MS Online (O365/Exchange) Services

    .Example
    Rain-Login -user john.doe@example.com
    Enter target password: **************
    [+] Successfully Logged In

    #>
    [CmdletBinding()]
    param
    (
    [Parameter(Mandatory=$False)]
    [string]$user
    )
    Write-Host ("\n \t \tWelcome to RainDance! \n \n")
    Write-Verbose 'Attempting to Authenticate...'
    if(!$user){
        $user = Read-Host -Prompt "Enter your target username"
    }
    $password = Read-Host -Prompt "Enter target password" -AsSecureString
    $creds = New-Object -typename System.Management.Automation.PSCredential -argumentlist $user, $password
    $password = $NULL
    Write-Host "[*] ATTEMPTING O365 LOGIN!"

    try{
        Connect-MsolService -Credential $creds -ErrorAction Stop
    }
    catch [System.Exception] {
        Write-Host "O365 - Authentication Error!"
        Break
    }
    $Global:LOGGED_IN_USER = $user
    Write-Host "[+] Successfully Logged In!"
    Write-Host "[*] Gathering general domain info..."
    $Global:O_DOMAINS = @(Get-MSOLDomain | Select-Object $_.Name)
    $Global:Licenses = Get-MsolSubscription
    $current_user_role = Get-MsolUserRole -UserPrincipalName $user
    if(!($current_user_role)){
        Write-Host "[-] Your current user has no administrative permissions."
    }
    else{
        Write-Host "[+] Your current user has the following administrative privileges!"
        Write-Output $current_user_role
        }
    Write-Host "[*] You currently have access to the following domains:"
    Write-Output $O_DOMAINS.Name
    Write-Host "[*] This company currently has the following products in use... n"
    Write-Output $Licenses.SkuPartNumber
    Write-Host "---------------------------------------------------------- n"

    try{
        Write-Host "[*] ATTEMPTING AZURE ACTIVE DIRECTORY LOGIN!"
        Connect-AzureAD -Credential $creds -ErrorAction Continue
        Write-Host "[+] Successfully authenticated to Azure!"
    } 
    catch { 
        Write-Host "Unable to Log into Azure AD. Either it is not provisioned, or you do not have access." 
    }

    return Get-Header
}

function check-login{
    if ($LOGGED_IN_USER -eq $NULL){
        Write-Host "[-] Woah cowboy. You gotta login first."
        return $False
    }
    else{
        return $True
    }
}

function Rain-GetUsers{
    if(!(check-login)){Break}
    Write-Host "[+] Gathering Usernames and details..."
    $users = @()
    foreach($user in (Get-MSOLUser -All)){
        $user_info = Get-MSOLUser -UserPrincipalName $user.UserPrincipalName       # Grab all user properties
        if ($user_info.IsLicensed -eq $True){
            $item = [Ordered]@{ 
                Username=$user_info.UserPrincipalName
                Name=$user_info.DisplayName
                SignIn=$user_info.SignInName
                Department=$user_info.Department
                Title=$user_info.Title
                Phone=$user_info.PhoneNumber
                Mobile=$user_info.MobilePhone
                Office=$user_info.Office
                City=$user_info.City
                State=$user_info.State
                Location=$user_info.UsageLocation
                LastPasswordChange=$user_info.LastPasswordChangeTimestamp
                LastDirSync=$user_info.LastDirSyncTime
                ObjectId=$user_info.ObjectId
            }
            $users += New-Object PSObject -Property $item
        }
    }

    if($O_USERS.length -eq 0){
        $Global:O_USERS = $users
    }
    Write-Host "[+] User collection complete. Use 'Rain-Show Users' command to view data."
    if($verbose){
        return $users
    }
}


function Rain-DumpUsers{
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True, position=1)]
        [string]$outfile,

        [Parameter(Mandatory=$False,ValueFromPipeline=$True, position=2)]
        [ValidateSet("csv","txt")]
        [string]$format = 'csv'
        )

    if($format -eq "csv"){
        $O_USERS | Sort-Object -Property Username | Export-Csv -path $outfile -NoTypeInformation
    }

    if($format -eq "txt"){
        $O_USERS | Sort-Object -Property Username | Format-Table > $outfile
    }
}

function Rain-GetRoles{
    if(!(check-login)){Break}
        Write-Host "[+] Gathering User Roles & Members..."
        $roles = @()
        foreach($role in (Get-MSOLrole)){
            $current_role = Get-MsolRole -ObjectId $role.ObjectId
            if($current_role.IsEnabled){
                if($current_role.Name.contains("Admin")){
                    $item = [Ordered]@{
                        Name=$($current_role.Name)
                        ObjectId=$($current_role.ObjectID)
                        Description=$($current_role.Description)
                        IsAdmin=$True
                    }
                    $roles += New-Object PSObject -Property $item
                }
                
                else{
                    $item = [Ordered]@{
                        Name=$($current_role.Name)
                        ObjectId=$($current_role.ObjectID)
                        Description=$($current_role.Description)
                        IsAdmin=$False
                    }
                    $roles += New-Object PSObject -Property $item
                }
            }
        }
        if($O_ROLES.length -eq 0){
            $Global:O_ROLES = $roles
        }
        Write-Host "[+] Role collection complete. Use 'Rain-Show Roles' command to view data."
    if($verbose){
        return $roles
    }
}

function Rain-DumpRoles{
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True, position=1)]
        [string]$outfile,

        [Parameter(Mandatory=$False,ValueFromPipeline=$True, position=2)]
        [ValidateSet("csv","txt")]
        [string]$format = 'csv'
        )

    if($format -eq "csv"){
        $O_ROLES | Sort-Object -Property Username | Export-Csv -path $outfile -NoTypeInformation
    }

    if($format -eq "txt"){
        $O_ROLES | Sort-Object -Property Username | Format-Table > $outfile
    }
}

function Rain-GetAdmins{
    if(!(check-login)){Break}
    Write-Host "[+] Gathering Administrator Accounts..."
    $admins = @()
    $Global_admins = @()
    $admin_roles = $O_ROLES | Where-Object{$_.IsAdmin -eq $True}
    foreach($admin_role in $admin_roles){
        if($admin_role.Name -eq "Company Administrator"){
            $Global_admins += Get-MsolRoleMember -All -RoleObjectID $admin_role.ObjectId
        }
        else{
            $admins += Get-MsolRoleMember -All -RoleObjectId $admin_role.ObjectId
        }
        Write-Host "================$($admin_role.Name)================"
        Write-Output $(Get-MSOLRoleMember -RoleObjectID $admin_role.ObjectId)
    }
    if($O_ADMINS.length -eq 0){
        $Global:O_ADMINS = $admins
    }
    if($O_GADMINS.length -eq 0){
        $Global:O_GADMINS = $Global_admins
    }
    Write-Host "[+] Admins collection Complete. Use 'Rain-Show Admins' or 'Rain-Show GlobalAdmins' command to view data."
    if($verbose){
        return $admins 
        return $Global_admins
    }
}

function Rain-DumpAdmins{
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True, position=1)]
        [string]$outfile,

        [Parameter(Mandatory=$False,ValueFromPipeline=$True, position=2)]
        [ValidateSet("csv","txt")]
        [string]$format = 'csv'
        )

    if($format -eq "csv"){
        $O_ADMINS | Sort-Object -Property Username | Export-Csv -path $outfile -NoTypeInformation
    }

    if($format -eq "txt"){
        $O_ADMINS | Sort-Object -Property Username | Format-Table > $outfile
    }
}

function Rain-GetGroup{
    if(!(check-login)){Break}
    Write-Host "[+] Gathering Mailing & Distribution Groups..."
    $groups = Get-MsolGroup -All
    if($O_GROUPS.length -eq 0){
        $Global:O_GROUPS = $groups
    }
    Write-Host "[+] Group collection Complete. Use 'Rain-Show Groups' command to view data."
    if($verbose){
        return $groups
    }
}

function Rain-DumpGroups{
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True, position=1)]
        [string]$outfile,

        [Parameter(Mandatory=$False,ValueFromPipeline=$True, position=2)]
        [ValidateSet("csv","txt")]
        [string]$format = 'csv'
        )

    if($format -eq "csv"){
        $O_GROUPS | Sort-Object -Property Username | Export-Csv -path $outfile -NoTypeInformation
    }

    if($format -eq "txt"){
        $O_GROUPS | Sort-Object -Property Username | Format-Table > $outfile
    }
}

function Rain-GetGroupMembers{
    if(!($O_Groups)){Write-Host "[-] Groups have not been gathered yet! Run Rain-GetGroup first."}
    else{
        Write-Host "[+] Gathering Group Members..."
        $group_member_list = @()
        foreach($group in $O_GROUPS){
            $g = Get-MsolGroupMember -GroupObjectId $group.ObjectId
            $group_info = [ordered]@{
                GroupName=$($group.DisplayName)
                Users=$($g)
            }
            $group_member_list += New-Object PSObject -property $group_info
        }
        $Global:O_GROUPMEMBERS = $group_member_list
        Write-Host {"[+] Group Member collection Complete. Use 'Rain-Show GroupMembers' command to view data."}
        if($verbose){
            return $group_member_list
        }
    } 
}

function Rain-GetDevices{
    if(!(check-login)){break}
    Write-Host "[+] Gathering active devices..."
    $device_list = @()
    $azure_devices = Get-AzureADDevice
    foreach($device in $azure_devices){
       $owner = Get-AzureADDeviceRegisteredOwner -ObjectId $device.ObjectId
       $item = [Ordered]@{
            Hostname=$($device.DisplayName)
            OS=$($device.DeviceOSType)
            Version=$($device.DeviceOSVersion)
            Trust=$($device.DeviceTrustType)
            ObjectId=$($device.ObjectId)
            Owner=$($owner.DisplayName)
            Username=$($owner.UserPrincipalName)
       }
        $device_list += New-Object PSObject -Property $item
   }
   $Global:O_DEVICES = $device_list
   if($verbose){
    return $devices_list
   }
}

function Rain-DumpDevices{
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True, position=1)]
        [string]$outfile,

        [Parameter(Mandatory=$False,ValueFromPipeline=$True, position=2)]
        [ValidateSet("csv","txt")]
        [string]$format = 'csv'
        )

    if($format -eq "csv"){
        $O_DEVICES | Sort-Object -Property Hostname | Export-Csv -path $outfile -NoTypeInformation
    }

    if($format -eq "txt"){
        $O_DEVICES | Sort-Object -Property Hostname | Format-Table > $outfile
    }
}

function Rain-GetAll{
    if(!(check-login)){Break}
    Write-Host("Gathering ALL of the Rain!")
    if($verbose){
        Rain-GetUsers -verbose
        Rain-GetDevices -verbose
        Rain-GetRoles -verbose
        Rain-GetAdmins -verbose
        Rain-GetGroup -verbose
        Rain-GetGroupMembers -verbose
    }

    Rain-GetUsers
    Rain-GetDevices
    Rain-GetRoles
    Rain-GetAdmins
    Rain-GetGroup
    Rain-GetGroupMembers
}

function Rain-Show{
    param(
        [Parameter (Mandatory=$True, ValueFromPipeline=$True, Position=1)]
        [ValidateSet("Users","Devices","Roles","Groups","GroupMembers","Admins","GlobalAdmins")]
        [string]$type,

        [string]$search
        )
    if($type -eq "Users"){
        if($O_USERS -eq $NULL){
            Write-Host "No Users gathered yet..."
            Break
        }
        $O_USERS | Sort-Object -Property Username | Format-Table
    }
    elseif($type -eq "Roles"){
        if($O_ROLES -eq $NULL){
            Write-Host "No Roles gathered yet..."
            Break
        }
        $O_ROLES | Sort-Object -Property Username | Format-Table
    }
    elseif($type -eq "Groups"){
        if($O_GROUPS -eq $NULL){
            Write-Host "No Groups gathered yet..."
            Break
        }
        $O_GROUPS | Sort-Object -Property Username | Format-Table
    }
    elseif($type -eq "GroupMembers"){
        if($O_GROUPMEMBERS -eq $NULL){
            Write-Host "No Group Members gathered yet..."
            Break
        }
        $search = Read-Host -prompt "Enter group to list members of... [blank = ALL GROUPS]"
        if($search -eq $NULL){
            $O_GROUPMEMBERS | Sort-Object -Property GroupName
        }
        else{
            $selection = $O_GROUPMEMBERS | Select-Object * | Where-Object {$_.GroupName -like "*$($search)*"}
            foreach($group in $selection){
                "==============$($group.GroupName)=============="
                $group.Users | Sort-Object -Property DisplayName | Format-Table
            }
        }
    }

    elseif($type -eq "Admins"){
        if($O_ADMINS -eq $NULL){
            Write-Host "No Admins gathered yet..."
            Break
        }
        $O_ADMINS | Sort-Object -Property Username | Format-Table
    }
    elseif($type -eq "GlobalAdmins"){
        if($O_GADMINS -eq $NULL){
            Write-Host "No Global Admins gathered yet..."
            Break
        }
        $O_GADMINS | Sort-Object -Property Username | Format-Table
    }
    elseif($type -eq "Devices"){
        if($O_DEVICES -eq $NULL){
            Write-Host "No devices have been gathered yet or no active sessions exist..."
            break
        }
        $O_DEVICES | Sort-Object -Property Hostname | Format-Table
    }
    else{
        Write-Host "Use one of the following types: Users, Roles, Groups, Admins"
    }
}

function Rain-DumpAll{
    [CmdletBinding()]
    param
    (
    [Parameter(Mandatory=$True, ValueFromPipeline=$True, position=1,
        HelpMessage="Enter a path to drop files into")]
    [string]$path,
    [Parameter(Mandatory=$False, ValueFromPipeline=$True, position=2,
        HelpMessage="Format of output file (csv or txt)")]
    [string]$format = 'csv'
    )

    if(!(test-path $path)){
        New-Item -ItemType Directory -Force -Path $path | Out-Null
    }

    if($format -eq 'txt'){
        $outfile = [io.path]::combine($path, "Rain_dump.txt")
        "========================+USERS+========================" > $outfile
        $O_USERS | Sort-Object -Property Username | Format-Table >> $outfile
        "========================+DEVICES+========================" >> $outfile
        $O_DEVICES | Sort-Object -Property Hostname | Format-Table >> $outfile
        "========================+ROLES+========================" >> $outfile
        $O_ROLES | Sort-Object -Property Username | Format-Table >> $outfile
        "========================+GROUPS+========================" >> $outfile
        $O_GROUPS | Sort-Object -Property Username | Format-Table >> $outfile
        "========================+GLOBAL ADMINS+========================" >> $outfile
        $O_GADMINS | Sort-Object -Property Username | Format-Table >> $outfile
        
    }
    else{
        $prefix = "Rain_"
        $userfile = $prefix + "users.csv"
        $rolefile = $prefix + "roles.csv"
        $groupfile = $prefix + "groups.csv"
        $adminfile = $prefix + "admins.csv"
        $fullpaths = @($userfile, $rolefile, $groupfile, $adminfile)
        foreach($i in $fullpaths){
            $full = [io.path]::combine($path, $i)
            if($i -like "*user*"){Rain-DumpUsers $full $format}
            elseif($i -like "*role*"){Rain-DumpRoles $full $format}
            elseif($i -like "*group*"){Rain-DumpGroups $full $format}
            elseif($i -like "*admin*"){Rain-DumpAdmins $full $format}
        }
    }
    Write-Host {"[+] ---COMPLETE---"}
}

function Rain-Company{
    if(!($COMPANY)){
        $Global:COMPANY = Get-MsolCompanyInformation
    }
    return $COMPANY
}

# Shows logged in user and domain information
function Get-Header{
    Write-Host ('============================= Welcome to Rain Dance =============================')
    if($LOGGED_IN_USER){
        Write-Output $("Current Domain: {0} | Alternate domains: {1}" -f $O_DOMAINS[0].Name, ($O_DOMAINS.Length - 1))
        Rain-Company
    }
    else{
        Write-Output "Not logged in. Run Rain-Login to get started."
    }
}

# Declare Main Variables as global (I'm sorry...powershell forces me to do horrible things :C )
function Rain-Main{
    Load-Modules
    $Global:LOGGED_IN_USER = $NULL
    $Global:O_Groups = $NULL
    $Global:O_DOMAINS = @()
    $Global:O_ADMINS = @()
    $Global:O_GADMINS = @()
    $Global:O_USERS = @()
    $Global:O_ROLES = @()
    $Global:O_DEVICES = @()
    Get-Banner
    check-import
    Rain-Login
    Get-Header
}

Rain-Main