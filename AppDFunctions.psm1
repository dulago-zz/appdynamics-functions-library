# discontinued. Use getConnection instead
function getLoginHeaders ($accountName, $username, $password) 
{   
    $pair = -join ($username, "@", $accountName, ":", $password)
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
    $basicAuthValue = "Basic $base64"

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", $basicAuthValue)
    $headers.Add("Accept", "application/json, text/plain, */*")
    $url = -join ("https://", $accountName, ".saas.appdynamics.com/controller/auth?action=login")
    try {
        $response = Invoke-WebRequest $url -Method 'GET' -Headers $headers -Body $body -SessionVariable session
        $headers.Add("Cookie", $response.Headers.'Set-Cookie')
    }
    catch {
        $StatusCode = $_.Exception.Response.StatusCode.value__
        return "[ERROR] Error obtaining login headers (Status code $StatusCode)"       
    }

    $token = $response.Headers.'Set-Cookie' -split "="
    $token = $token -split ";"
    $headers.Add("X-CSRF-TOKEN", $token[6])

    return $headers
}

# discontinued. Use getConnection instead
function getLoginSession ($accountName, $username, $password) 
{
    $pair = -join ($username, "@", $accountName, ":", $password)
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
    $basicAuthValue = "Basic $base64"

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", $basicAuthValue)
    $headers.Add("Accept", "application/json, text/plain, */*")
    $url = -join ("https://", $accountName, ".saas.appdynamics.com/controller/auth?action=login")
    try {
        $response = Invoke-WebRequest $url -Method 'GET' -Headers $headers -Body $body -SessionVariable session
        $headers.Add("Cookie", $response.Headers.'Set-Cookie')
    }
    catch {
        $StatusCode = $_.Exception.Response.StatusCode.value__
        return "[ERROR] Error obtaining login headers (Status code $StatusCode)"       
    }

    return $session
}

# opens a connection with a Controller and return the login headers and session info
function getConnection ($accountName, $username, $password) 
{
    $pair = -join ($username, "@", $accountName, ":", $password)
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
    $basicAuthValue = "Basic $base64"

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", $basicAuthValue)
    $headers.Add("Accept", "application/json, text/plain, */*")
    $url = -join ("https://", $accountName, ".saas.appdynamics.com/controller/auth?action=login")
    try {
        $response = Invoke-WebRequest $url -Method 'GET' -Headers $headers -Body $body -SessionVariable session
        $headers.Add("Cookie", $response.Headers.'Set-Cookie')
    }
    catch {
        $StatusCode = $_.Exception.Response.StatusCode.value__
        return "[ERROR] Error obtaining login headers (Status code $StatusCode)"       
    }

    $token = $response.Headers.'Set-Cookie' -split "="
    $token = $token -split ";"
    $headers.Add("X-CSRF-TOKEN", $token[6])
    
    $connection = New-Object -TypeName PSCustomObject -Property @{}
    $connection | Add-Member -Force -MemberType NoteProperty -Name headers -Value $headers
    $connection | Add-Member -Force -MemberType NoteProperty -Name session -Value $session

    return $connection
}

# get the name of an application by its ID
function getAppById ($appID, $accountName, $connection) 
{
    $url = -join ("https://", $accountName, ".saas.appdynamics.com/controller/rest/applications/", $appID, "?output=JSON")
    try {
        $response = Invoke-WebRequest $url -Method 'GET' -Headers $connection.headers | ConvertFrom-Json
        return $response.name    
    }
    catch {
        $StatusCode = $_.Exception.Response.StatusCode.value__
        return "[ERROR] Error getting app ID (Status code $StatusCode)"
    }
}

# get the ID of an application by its name
function getIdByAppName ($appName, $accountName, $connection) 
{
    $appNameEncoded = [uri]::EscapeDataString($appName)
    $url = -join ("https://", $accountName, ".saas.appdynamics.com/controller/rest/applications/", $appNameEncoded, "?output=JSON")
    try {
        $response = Invoke-RestMethod $url -Method 'GET' -Headers $connection.headers
        return $response.id    
    }
    catch {
        $StatusCode = $_.Exception.Response.StatusCode.value__
        return "[ERROR] Error getting app name (Status code $StatusCode)"
    }
}

# get the name of a backend by its ID
function getBackendById ($backendID, $accountName, $connection) 
{
    $url = -join ("https://", $accountName, ".saas.appdynamics.com/controller/restui/backendFlowMapUiService/backend/", $backendID, "?time-range=last_12_hours.BEFORE_NOW.-1.-1.60&mapId=-1")
    try {
        $response = Invoke-WebRequest $url -Method 'GET' -WebSession $connection.session -Headers $connection.headers
        return $response.name    
    }
    catch {
        $StatusCode = $_.Exception.Response.StatusCode.value__
        # Write-Host $StatusCode ## DEBUG
        return "[ERROR] Error getting backend name (Status code $StatusCode)"
    }  
}

# return an object with informations of all uninstrumented backends of an application
function getBackendList ($appName, $accountName, $connection) 
{
    $appID = getIdByAppName -appName $appName -accountName $accountName -connection $connection
    $url = -join ("https://", $accountName, ".saas.appdynamics.com/controller/rest/applications/", $appID, "/backends?output=JSON")
    try {
        $response = Invoke-RestMethod $url -Method 'GET' -Headers $connection.headers
        return $response
    }
    catch {
        $StatusCode = $_.Exception.Response.StatusCode.value__
        return "[ERROR] Error getting backend list (Status code $StatusCode)"
    }
}

# return an object with informations of all servers hosting an application
function getAppServers ($appName, $accountName, $connection) 
{
    $appID = getIdByAppName -appName $appName -accountName $accountName -connection $connection

    $url = -join ("https://", $accountName, ".saas.appdynamics.com/controller/rest/applications/", $appID, "/nodes?output=JSON")
    try {
        $response = Invoke-RestMethod $url -Method 'GET' -Headers $connection.headers
        return $response
    }
    catch {
        $StatusCode = $_.Exception.Response.StatusCode.value__
        return "[ERROR] Error getting server list (Status code $StatusCode)"
    }
}

# get the grid of dependencies of an application with its specific metrics
function getAppGrid ($appName, $accountName, $connection) 
{
    $appID = getIdByAppName -appName $appName -accountName $accountName -connection $connection

    $url = -join ("https://", $accountName, ".saas.appdynamics.com/controller/restui/applicationFlowMapUiService/application/", $appID, "?time-range=last_12_hours.BEFORE_NOW.-1.-1.60&mapId=-1&forceFetch=false&baselineId=17148420")
    try {
        $response = Invoke-RestMethod $url -Method 'GET' -WebSession $connection.session -Headers $connection.headers
        if ($null -eq $response.edges) {
            return "AppDynamics API did not return the full dependency grid. Please try again in a moment"
        }
        else {
            return $response
        }
    }
    catch {
        $StatusCode = $_.Exception.Response.StatusCode.value__
        return "[ERROR] Error getting app dependency grid (Status code $StatusCode)"
    }
}

# list the name of all dependencies of an application (other applications and backends)
function getAppDependencies ($appName, $accountName, $connection) 
{
    $dependencies = @()
    $grid = getAppGrid -appName $appName -accountName $accountName -connection $connection
    foreach ($edge in $grid.edges) {
        if ($edge.targetNodeDefinition.entityType -eq "APPLICATION") {
            $dependency = getAppById -appID $edge.targetNodeDefinition.entityId -accountName $accountName -connection $connection
            $dependencies += $dependency
        }
    }
    $backendList = getBackendList -appName $appName -accountName $accountName -connection $connection
    foreach ($backend in $backendList) {
        $dependencies += $backend.name
    }
    $serverList = getAppServers -appName $appName -accountName $accountName -connection $connection
    foreach ($server in $serverList) {
        $dependencies += $serverList.machineName 
    }

    return $dependencies    
}

# list all the dependencies of an application, as well as the type of dependency (WCF, datadabase, application, etc)
function getAppDependenciesWithType ($appName, $accountName, $connection) 
{
    $dependencies = @()
    $grid = getAppGrid -appName $appName -accountName $accountName -connection $connection
    foreach ($edge in $grid.edges) {
        if ($edge.targetNodeDefinition.entityType -eq "APPLICATION") {
            $dependency = getAppById -appID $edge.targetNodeDefinition.entityId -accountName $accountName -connection $connection
            $dependencies += "$dependency | Application"
        }
    }
    $backendList = getBackendList -appName $appName -accountName $accountName -connection $connection
    foreach ($backend in $backendList) {
        $dependency = "$($backend.name) | $($backend.exitPointType)"
        $dependencies += $dependency
    }
    $serverList = getAppServers -appName $appName -accountName $accountName -connection $connection
    $count = 0
    foreach ($server in $serverList) {
        $dependency = "$($serverList[$count].machineName ) | Server"
        $dependencies += $dependency
        $count++
    }

    return $dependencies   
}

# export the dependencies of an application (with types) to a file separated by | 
function exportDependenciesCSV ($appName, $accountName, $connection, $outputFilename) 
{
    $dependencies = getAppDependenciesWithType -appName $appName -accountName $accountName -connection $connection
    if ($null -eq $outputFilename) {
        $outputFilename = "output.csv"
    }    
    foreach ($dependency in $dependencies) {
        # Add-Content -Path $filename -Value "$appName, $dependency" -Force
        Add-Content -Path $outputFilename -Value "$dependency" -Force
    }
}

# export the dependencies of a list of applications (with types) to a file separated by |
function exportListAppDependenciesCSV ($appListFile, $accountName, $connection, $outputFilename) 
{
    $appList = Get-Content $appListFile
    foreach ($appName in $appList) {
        $dependencies = getAppDependenciesWithType -appName $appName -accountName $accountName -connection $connection

        foreach ($dependency in $dependencies) {
            Add-Content -Path $outputFilename -Value "$appName | $dependency" -Force

        }   
    }
}

# installs or update the .NET Agent on a Windows machine (local or remote)
# taken from https://www.appdynamics.com/community/exchange/extension/dotnet-agent-installation-with-remote-management-powershell-extension/
function global:Install-Agent
{
	# [CmdletBinding()]
	# PARAM(
    #     [Parameter(Mandatory=$true, Position=0)]
    #       [ValidateScript({(($_ -ne $null) -and ($_.Count -ge 1) -and ($_.Count -le 2))})]
    #       [STRING[]] $SetupFile=$null,
    #     [Parameter(Mandatory=$false, Position=1)]
    #       [ValidateScript({($_ -eq $null) -or (Test-Path $_ -PathType Leaf)})]
    #       [STRING] $TemplateFile=$null,
    #     [Parameter(Mandatory=$false, ValueFromPipeline=$true)]
    #       [STRING[]] $ComputerName=$null,
    #     [STRING] $RemoteShare="c$\temp\AppDynamics\Install\",
    #     [STRING] $RemotePath="c:\temp\AppDynamics\Install\",
    #     [Switch] $RestartIIS,
    #     [Switch] $SharePointInstall,
    #     [STRING[]] $RestartWindowsServices=$null,
    #     [Hashtable] $Arguments=$null
	# )

    # process
    # {

    #    #---------Start VISH---------
        
    #     function Get-WMIService
    #       {               
    #              $ServiceName = Get-Service -Name wmiApSrv              
               
    #              if ($ServiceName -ne $null)          
    #               {
    #                  if ($ServiceName.Status -eq "Stopped")
    #                  {
    #                     try {
    #                         Start-Service $ServiceName.DisplayName | Out-File log.txt -Append    
    #                     }
    #                     catch {
    #                         return "[ERROR] Unable to start WMI service on server"
    #                     }
                        
                        
    #                     #     $confirmation = Read-Host $ServiceName.DisplayName "service is stopped. Do you want to start the service and proceed installation?(Y/N)"                         
    #                     #    if($confirmation -eq 'y') #if($ConfirmResult)
    #                     #    {
    #                     #         Write-Host "Starting Service...."
    #                     #         Start-Service $ServiceName.DisplayName
    #                     #         Write-Host "Starting " $ServiceName.DisplayName " Service is now started"
    #                     #    }else
    #                     #    {
    #                     #         Write-Host $ServiceName.DisplayName "is stopped.In order to continue the installation, start the service"
    #                     #         Throw
    #                     #    }
    #                     #     Write-Host "Service Stopped"
    #                  }else{
                     
    #                         if ($ServiceName.Status -eq "Running")
    #                         { 
    #                                 #Write-Host $ServiceName.DisplayName "service is already started"
    #                                 Add-Content log.txt "Servico WMI esta ativo`n"
    #                         }
    #                 }
    #               }else
    #                  {
    #                     Add-Content log.txt "Servico WMI nao encontrado`n"
    #                  #Write-Warning $ServiceName.DisplayName "Service DoesNot Exist."
    #                  #Throw
                 
    #                  } 
    #         }


    #          function Get-COMService
    #           {               
    #              $ServiceName = Get-Service -Name COMSysApp               
                                 
               
    #              if ($ServiceName -ne $null)          
    #               {
    #                  if ($ServiceName.Status -eq "Stopped")
    #                  {
    #                         #$ConfirmResult = Ask-Confirm -ServiceName $ServiceName 
    #                         $confirmation = Read-Host $ServiceName.DisplayName "service is stopped. Do you want to start the service and proceed installation?(Y/N)"
    #                         if($confirmation -eq 'y') #if($ConfirmResult)
    #                         {
    #                             Write-Host "Starting Service...."  
    #                             Start-Service $ServiceName
    #                             Write-Host "Starting " $ServiceName.DisplayName " Service is now started"
    #                             #Write-Host "Service Stopped"
    #                          }else
    #                          {
    #                             Write-Host $ServiceName.DisplayName "is stopped.In order to continue the installation, start the service"
    #                             #Break
    #                             Throw
    #                          }

    #                  }else{
                     
    #                         if ($ServiceName.Status -eq "Running")
    #                         { 
    #                                 Write-Host $ServiceName.DisplayName "service is already started"
    #                         }
    #                 }
    #               }else
    #                  {
                 
    #                  Write-Warning $ServiceName.DisplayName "Service DoesNot Exist."
    #                  Throw
                 
    #                  } 
    #         }   
        
    #         <#   if($ComputerName -ne $null)
    #             {
    #               foreach($computer in $ComputerName)
    #                {
                      
    #                   $Result =  Test-ComputerConnection($computer)
    #                   if($Result)
    #                    {
    #                      if($computer -ne $null)
    #                      {  
    #                       $code = Get-CodeInternal(Get-Command Get-WMIService)                          
	# 	                  Invoke-Command -ComputerName $computer -ScriptBlock $code 
    #                       $code = Get-CodeInternal(Get-Command Get-COMService)                          
	# 	                  Invoke-Command -ComputerName $computer -ScriptBlock $code 
    #                      }
                   
    #                    }
               
    #                }
    #             }
    #             else               
    #             {
    #             $code = Get-CodeInternal(Get-Command Get-WMIService) 
    #             Invoke-Command -ScriptBlock $code 
    #             $code = Get-CodeInternal(Get-Command Get-COMService) 
	# 	        Invoke-Command -ScriptBlock $code                 
    #             } #>

    #    #---------END----------
    #     function Setup-MsiLocal(
    #         [string] $Setup64File,
    #         [string] $Setup32File,
    #         [string] $TemplateFile,
    #         [Bool] $RestartIIS,
    #         [String[]] $RestartWindowsServices,
    #         [Bool] $SharePointInstall,
    #         [Hashtable] $Arguments
    #         )
    #     {
           
    #         $setup_file = $Setup32File
	#         if(Get-64ArchitectureShared) { $setup_file = $Setup64File }

    #         if(([string]::IsNullOrEmpty($setup_file) -or (-Not (Test-Path $setup_file -PathType Leaf))))
    #         {
    #             Throw "Agent install file $setup_file is not found."
    #         }

    #         $version = Get-MsiProductVersionShared $setup_file

    #         $agent = Get-AgentShared
    #         if($agent -ne $null)
    #         {
    #             $local_version = [Version]$agent.DisplayVersion
    #             if($version.CompareTo($local_version) -eq 1)
    #             {
    #                 Stop-ApplicationShared $RestartIIS $RestartWindowsServices
    #                 $exitcode = Uninstall-AgentShared

    #                 if($exitcode -eq 0)
    #                 {
    #                     $exitcode = Install-AgentShared $setup_file $TemplateFile $Arguments
    #                     if($exitcode -eq 0)
    #                     {
    #                         Restart-CoordinatorShared
    #                         Start-ApplicationShared $RestartIIS $RestartWindowsServices

    #                         $result = @{Result=$true; Message=".NET agent $version successfully upgraded from $local_version."}
    #                         New-Object PSObject –Property $result

    #                         RegistryChanges-Shared($SharePointInstall)
    #                     }
    #                     else
    #                     {
    #                         $result = @{Result=$false; Message=".NET agent $version install failed. Error code: $exitcode"}
    #                         New-Object PSObject –Property $result
    #                     }
    #                 }
    #                 else
    #                 {
    #                     $result = @{Result=$false; Message=".NET agent $local_version uninstall failed. Error code: $exitcode"}
    #                     New-Object PSObject –Property $result
    #                 }
    #             }
    #             else
    #             {
    #                 $result = @{Result=$false; Message="Installed version: $local_version. New version: $version. No upgrade required."}
    #                 New-Object PSObject –Property $result
    #             }
    #         }
    #         else
    #         {
    #             $exitcode = Install-AgentShared $setup_file $TemplateFile $Arguments
    #             if($exitcode -ne 0)
    #             {
    #                 $result = @{Result=$false; Message=".NET agent $version install failed. Error code: $exitcode"}
    #                 New-Object PSObject –Property $result
    #             }
    #             else
    #             {
    #                 Restart-CoordinatorShared
    #                 Restart-ApplicationShared $RestartIIS $RestartWindowsServices

    #                 $result = @{Result=$true; Message=".NET agent $version successfully installed."}
    #                 New-Object PSObject –Property $result

    #                 RegistryChanges-Shared($SharePointInstall)
    #             }
    #         }
    #     }

    #     function Setup-MsiRemote(
    #         [STRING[]] $ComputerName,
    #         [STRING] $Setup64File,
    #         [STRING] $Setup32File,
    #         [STRING] $TemplateFile,
    #         [STRING] $RemoteShare,
    #         [STRING] $RemotePath,
    #         [Bool] $RestartIIS,
    #         [STRING[]] $RestartWindowsServices,
    #         [bool] $SharePointInstall,
    #         [Hashtable] $Arguments)
    #     {
    #         #Copy files for remote install
    #         [array] $files = @()
    #         [string]$remote_setup32 = $null
    #         [string]$remote_setup64 = $null
    #         [string]$remote_template = $null
            
    #         if((-Not [string]::IsNullOrEmpty($Setup64File)) -and (Test-Path -Path $Setup64File -PathType Leaf)) 
    #         {
    #             $files += $Setup64File 
    #             $remote_setup64 = Join-Path -Path $RemotePath -ChildPath (Split-Path $Setup64File -Leaf)
    #         }

    #         if((-Not [string]::IsNullOrEmpty($Setup32File)) -and (Test-Path -Path $Setup32File -PathType Leaf))
    #         {
    #             $files += $Setup32File 
    #             $remote_setup32 = Join-Path -Path $RemotePath -ChildPath (Split-Path $Setup32File -Leaf)
    #         }

    #         if((-Not [string]::IsNullOrEmpty($TemplateFile)) -and (Test-Path -Path $TemplateFile -PathType Leaf)) 
    #         {
    #             $files += $TemplateFile
    #             $remote_template = Join-Path -Path $RemotePath -ChildPath (Split-Path $TemplateFile -Leaf)
    #         }

    #         Copy-FilesToRemoteComputersInternal $files $ComputerName $RemoteShare
            
    #         #Run the installer
    #         $code = Get-CodeInternal(Get-Command Setup-MsiLocal)            
	#         Invoke-Command -ComputerName $ComputerName -ScriptBlock $code -ArgumentList $remote_setup64, $remote_setup32, $remote_template, $RestartIIS, $RestartWindowsServices, $SharePointInstall ,$Arguments | select -ExcludeProperty RunspaceId
    #     }


    #     # Parse setup file names into 32 and 64 bit by thecking the names
    #     $Setup64File = $null
    #     $Setup32File = $null

    #     foreach($file in $SetupFile)
    #     {
    #         # check if file name ends with '64' or not
    #         if((-Not [string]::IsNullOrEmpty($file)) -and (Test-Path -Path $file -PathType Leaf))
    #         {
    #             $name = [System.IO.Path]::GetFileNameWithoutExtension($file)
    #             if($name.Contains("64")) { $Setup64File = $file }
    #             else { $Setup32File = $file }
    #         }
    #     }

    #     # Main logic - validate parameters
    #     if(-Not ((Test-Path -Path $Setup64File -PathType Leaf) -or (Test-Path -Path $Setup32File -PathType Leaf)))
    #     {
    #         Throw "Agent msi files were not found."
    #     }

    #     #Test ComputerName value
    #     if($ComputerName -ne $null)
    #     {
    #        foreach($computer in $ComputerName)
    #        {
    #          $Result =  Test-ComputerConnection($computer)
    #          if($Result)
    #           {
    #             $code = Get-CodeInternal(Get-Command Get-WMIService)                          
	# 	        Invoke-Command -ComputerName $computer -ScriptBlock $code 
    #             $code = Get-CodeInternal(Get-Command Get-COMService)                          
	# 	        Invoke-Command -ComputerName $computer -ScriptBlock $code 
    #             Setup-MsiRemote $computer $Setup64File $Setup32File $TemplateFile $RemoteShare $RemotePath $RestartIIS $RestartWindowsServices $SharePointInstall $Arguments 
    #           }
    #        }
         
    #         #Setup-MsiRemote $ComputerName $Setup64File $Setup32File $TemplateFile $RemoteShare $RemotePath $RestartIIS $RestartWindowsServices $Arguments
    #     }
    #     else
    #     {
    #         #Setup locally
    #         $code = Get-CodeInternal(Get-Command Get-WMIService) 
    #         Invoke-Command -ScriptBlock $code 
    #         $code = Get-CodeInternal(Get-Command Get-COMService) 
	# 	    Invoke-Command -ScriptBlock $code                 
    #         Setup-MsiLocal $Setup64File $Setup32File $TemplateFile $RestartIIS $RestartWindowsServices $SharePointInstall $Arguments 
    #     }
    # }
}

# get the version of the .NET Agent on a windows machine (local or remote)
# taken from https://www.appdynamics.com/community/exchange/extension/dotnet-agent-installation-with-remote-management-powershell-extension/
function global:Get-Agent 
{
    [CmdletBinding()]
    PARAM(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [STRING[]] $ComputerName = $null
    )

    process {
        function Get-AgentLocal() {
            $agent = Get-AgentShared
            $version = $null
            if ($null -ne $agent) { $version = [Version]$agent.DisplayVersion }
            else { [version] "0.0.0.0" }
            $version 
        }

        #Test ComputerName value
        if ($null -ne $ComputerName) {
          
            foreach ($computer in $ComputerName) {
                $Result = Test-ComputerConnection($computer)
                if ($Result) {
                    $verbose = Get-VerboseShared
                    $code = Get-CodeInternal(Get-Command Get-AgentLocal)
                    Invoke-Command -ComputerName $computer -ScriptBlock $code -Verbose:$verbose | select -ExcludeProperty RunspaceId
                                                        
                }
            }
        }
        else {
            Get-AgentLocal
        }
    }
}

# install or update the .NET Agent of a given list of Windows machines
function installAgentBatch ($serverList, $MSIFIle, [Switch] $restartIIS) 
{
    $updated, $noAccess, $notUpdated, $updateError = 0    

    Write-Host "$(Get-Date) Reading server list"
    $serverList = Get-Content -Path 'serverList.txt' 
    $MSIVersion = $MSIFIle.Split("-.")   

    foreach ($server in $serverList) {
        if (Test-Connection $server -Quiet -Count 1) {
            $agentVersion = Get-Agent -ComputerName $server
                
            elseif ( ($agentVersion.Major -lt $MSIVersion[1]) -or (($agentVersion.Major -eq $MSIVersion[1]) -and ($agentVersion.Minor -lt $MSIVersion[2])) ) {
                Write-Host "$(Get-Date) [INFO] Updating server $server (Current version $agentVersion)"
                if($restartIIS -eq $true){
                    $statusUpdate = Install-Agent $agentMSI -ComputerName $server -RestartIIS
                }
                else{
                    $statusUpdate = Install-Agent $agentMSI -ComputerName $server
                }
                
                if ($statusUpdate.Message -like "*No upgrade required*" -or ($statusUpdate.Message -like "*no upgrade required*")) {
                    Write-Host "$(Get-Date) [INFO] Server $server already up do date. No action required"
                    $notUpdated ++
                }            

                elseif ($statusUpdate.Message -like "*successfully upgraded*") {
                    Write-Host "$(Get-Date) [INFO] Server $server successfully updated"
                    $updated ++
                }            
    
                else {
                    Write-Host "$(Get-Date) [ERROR] Could not update server $server"
                    $updateEror ++
                }
                
            }      
            
            elseif ( ($agentVersion.Major -eq $MSIVersion[1]) -and ($agentVersion.Minor -eq $MSIVersion[2]) ) {
                Write-Host "$(Get-Date) [INFO] Server $server already up do date. No action required"
                $notUpdated ++
            }   

            elseif (($agentVersion.Major -eq 4) -and ($agentVersion.Minor -lt 3)) {
                Write-Host "$(Get-Date) [WARN] Server $server is currently with a very old version ($agentVersion). Proceed with manual installation"
                $notUpdated ++
            }
            
            else {
                if($restartIIS -eq $true){
                    $statusUpdate = Install-Agent $agentMSI -ComputerName $server -RestartIIS
                }
                else{
                    $statusUpdate = Install-Agent $agentMSI -ComputerName $server
                }
                $time = Get-Date
                if ($statusUpdate.Message -like "*successfully*") {
                    Write-Host "$(Get-Date) [INFO] Server $server didn't have an agent installed. Agent installed succesfully"
                    $updated ++
                }
                else {
                    Write-Host "$(Get-Date) [ERROR] Server $server didn't have an agent installed. Unable to install the agent remotely"
                    $updateError ++
                }
    
            }
        }
        else {
            Write-Host "$(Get-Date) [ERROR] Unable to connect to server $server"
            $noAccess ++
        }
    }
}

# get the config.xml file from a server and returns it as a PS Object 
function getAppAgentConfigFile ($serverName, $agentConfigFolder) 
{
    if ($null -eq $agentConfigFolder) {
        $path = "C:\ProgramData\AppDynamics\DotNetAgent\Config\config.xml"
    }
    else{
        $path = -join($agentConfigFolder, "\config.xml") 
    }
    try {
        [xml]$appAgentConfig = Invoke-Command -ScriptBlock {Get-Content $using:path} -ComputerName $serverName
        return $appAgentConfig   
    }
    catch {
        return "[ERROR] Error getting config file from server $serverName. Check connection and credentials"
    }
}

# saves changes made to an appagent config file on a remote server
function saveAppAgentConfigFile([xml]$appAgentConfig, $serverName, $agentConfigFolder)
{
    if ($null -eq $agentConfigFolder) {
        $path = "C:\ProgramData\AppDynamics\DotNetAgent\Config\config.xml"
    }
    else{
        $path = -join($agentConfigFolder, "\config.xml") 
    }

    try {
        Invoke-Command -ComputerName $serverName -ScriptBlock {$function:appAgentConfig.Save($using:path)}
    }
    catch {
        $ErrorMessage = $_.Exception.Response.FullyQualifiedErrorId.value__
        return "[ERROR] Unable to save config file on server $serverName. Error message: $ErrorMessage"
    }
}

# sets up the basic tags needed for a config file after a fresh install of the .NET agent
function setEmptyConfig ([xml]$appAgentConfig)
{
    $appAgentConfig.'appdynamics-agent'.controller.SetAttribute("port", "443")
    $appAgentConfig.'appdynamics-agent'.controller.SetAttribute("ssl", "true")
    $appAgentConfig.'appdynamics-agent'.controller.SetAttribute("enable_tls12", "true")

    $appAgentConfig.'appdynamics-agent'.controller.RemoveChild($appAgentConfig.'appdynamics-agent'.controller.application)
    $applicationElement = $appAgentConfig.CreateNode("element", "applications", "")
    $childApp = $appAgentConfig.CreateNode("element", "application", "")
    $childApp.SetAttribute("name", "DefaultApplication")
    $childApp.SetAttribute("default", "true")
    $applicationElement.AppendChild($childApp)
    $appAgentConfig.'appdynamics-agent'.controller.AppendChild($applicationElement)

    $account = $appAgentConfig.CreateNode("element", "account","")
    $account.SetAttribute("name", "default")
    $account.SetAttribute("password", "default")
    $appAgentConfig.'appdynamics-agent'.controller.AppendChild($account)

    $appAgents = $appAgentConfig.CreateNode("element", "app-agents","")
    $profReinstrumentation = $appAgentConfig.CreateNode("element", "profiler","")
    $profReinstrumentation.InnerXml = "<runtime-reinstrumentation />"
    $IIS = $appAgentConfig.CreateNode("element", "IIS","")
    $automatic = $appAgentConfig.CreateNode("element", "automatic", "")
    $automatic.SetAttribute("enabled", "true")

    $IIS.AppendChild($automatic)
    $appAgents.AppendChild($profReinstrumentation)
    $appAgents.AppendChild($IIS)
    $appAgentConfig.'appdynamics-agent'.AppendChild($appAgents)

    $applications = $appAgentConfig.CreateNode("element", "applications", "")
    $application = $appAgentConfig.CreateNode("element", "application", "")
    $application.SetAttribute("controller-application", "DefaultApplication")
    $application.SetAttribute("path", "DefaultApplication")
    $application.SetAttribute("site", "DefaultApplication")
    $tier = $appAgentConfig.CreateNode("element", "tier", "")
    $tier.SetAttribute("name", "DefaultApplication")

    $application.AppendChild($tier)
    $applications.AppendChild($application)
    $appAgentConfig.'appdynamics-agent'.'app-agents'.IIS.AppendChild($applications)
}

# set controller information on an empty config file
function setControllerOnConfig ([xml]$appAgentConfig, $accountName)
{
    $hostname = -join($accountName, ".saas.appdynamics.com")
    $appAgentConfig.'appdynamics-agent'.controller.host = $hostname
    $appAgentConfig.'appdynamics-agent'.controller.port = "443"
    $appAgentConfig.'appdynamics-agent'.controller.ssl = "true"
    $appAgentConfig.'appdynamics-agent'.controller.enable_tls12 = "true"
    $appAgentConfig.'appdynamics-agent'.controller.account.name = $accountName
}

# get license key for a given license rule and inserts it on the appagent config file
function setLicenseOnConfig ([xml]$appAgentConfig, $accountName, $connection, $licenseRuleName)
{
    $licenseRuleEncoded = [uri]::EscapeDataString($licenseRuleName)
    #$controllerHost = -join($accountName,".saas.appdynamics.com")
    $url = -join("https://", $accountName, ".saas.appdynamics.com/mds/v1/license/rules/name/", $licenseRuleEncoded)
    try {
        $response =  Invoke-RestMethod -Uri $url -Method 'GET' -Headers $connection.headers
        $appAgentConfig.'appdynamics-agent'.controller.account.password = "$($response.access_key)"    
        return "[INFO] License rule $licenseRuleName added to appagent config file with key $($response.access_key)"
    }
    catch {
        $StatusCode = $_.Exception.Response.StatusCode.value__
        return "[ERROR] Error obtaining license details (Status code $StatusCode)"
    }
}

# adds an IIS web application to an appagent config file
function setWebAppOnConfig([xml]$appAgentConfig, $appName, $appPath, $siteName)
{
    $controllerApp = $appAgentConfig.CreateNode("element", "application", "")
    $controllerApp.SetAttribute("name", $appName)
    $appAgentConfig.'appdynamics-agent'.controller.applications.AppendChild($controllerApp)

    $application = $appAgentConfig.CreateNode("element", "application", "")
    $application.SetAttribute("controller-application", $appName)
    $application.SetAttribute("path", $appPath)
    $application.SetAttribute("site", $siteName)
    $tier = $appAgentConfig.CreateNode("element", "tier", "")
    $tier.SetAttribute("name", $appName)
    $application.AppendChild($tier)
    
    $appAgentConfig.'appdynamics-agent'.'app-agents'.IIS.applications.AppendChild($application)
}

# returns an object containing all web applications deployed on localhost's IIS 
function getDeployedAppsLocal
{
    $webApplications = Get-WebApplication | ConvertTo-Json | ConvertFrom-Json 
    $i = 0
    $appList = @{}
    foreach ($application in $webApplications) 
    {
        if (Test-Path $application.PhysicalPath )
        {
            $site = $application.ItemXPath.Split("'")
            $site = $site[1]
            $appList[$i] = @{}
            $appList[$i]["name"] = -join($site, $application.path)
            $appList[$i]["path"] = $application.path
            $applist[$i]["site"] = $site
        }    
    }
    return $appList
}

# returns an object containing all web applications deployed on a remote server's IIS
function getDeployedAppsRemote($serverName)
{
    try {
        $webApplications = Invoke-Command -ComputerName $serverName -ScriptBlock ${function:getDeployedAppsLocal}
        return $webApplications
    }
    catch {
        return "[ERROR] Error getting deployed applications from server $serverName"
    }    
}

# configures all deployed IIS applications on a appagent config file that are not already configured
function setIisAppsOnConfig([xml]$appAgentConfig, $webApplications)
{
    for ($i = 0; $i -lt $webApplications.Count; $i++) {
        if (($null -eq ($appAgentConfig.'appdynamics-agent'.controller.applications | findstr WebApp/localiza/NPCProcessador2)) -and ($null -eq $appAgentConfig.'appdynamics-agent'.'app-agents'.IIS.applications)) {
            $appName = $webApplications["name"]
            $appPath = $webApplications["path"]
            $siteName = $webApplications["site"]
            try {
                setWebAppOnConfig -appAgentConfig $appAgentConfig -appName $appName -appPath $appPath -siteName $siteName
            }
            catch {
                return "[ERROR] Unable to set application $appName on config.xml file"
            }
        }
    }
}