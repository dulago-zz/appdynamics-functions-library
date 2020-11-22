# discontinued. Use getConnection instead
function getLoginHeaders ($accountName, $username, $password) {  
    ##MOCK
    # $username = "132161"
    # $password = ""
    # $accountName = "localizabrasil"
    ##
    
    $pair = -join($username,"@",$accountName,":",$password)
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
    $basicAuthValue = "Basic $base64"

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", $basicAuthValue)
    $headers.Add("Accept", "application/json, text/plain, */*")
    $url = -join("https://",$accountName,".saas.appdynamics.com/controller/auth?action=login")
    try {
        $response = Invoke-WebRequest $url -Method 'GET' -Headers $headers -Body $body -SessionVariable session
        $headers.Add("Cookie", $response.Headers.'Set-Cookie')
    }
    catch {
        $StatusCode = $_.Exception.Response.StatusCode.value__
        return "Error obtaining login headers (Status code $StatusCode)"       
    }

    $token = $response.Headers.'Set-Cookie' -split "="
    $token = $token -split ";"
    $headers.Add("X-CSRF-TOKEN", $token[6])

    return $headers
}

# discontinued. Use getConnection instead
function getLoginSession ($accountName, $username, $password) {
    ##MOCK
    # $username = "132161"
    # $password = ""
    # $accountName = "localizabrasil"
    ##
    
    $pair = -join($username,"@",$accountName,":",$password)
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
    $basicAuthValue = "Basic $base64"

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", $basicAuthValue)
    $headers.Add("Accept", "application/json, text/plain, */*")
    $url = -join("https://",$accountName,".saas.appdynamics.com/controller/auth?action=login")
    try {
        $response = Invoke-WebRequest $url -Method 'GET' -Headers $headers -Body $body -SessionVariable session
        $headers.Add("Cookie", $response.Headers.'Set-Cookie')
    }
    catch {
        $StatusCode = $_.Exception.Response.StatusCode.value__
        return "Error obtaining login headers (Status code $StatusCode)"       
    }

    return $session
}

# opens a connection with a Controller and return the login headers and session info
function getConnection ($accountName, $username, $password) {
    $pair = -join($username,"@",$accountName,":",$password)
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
    $basicAuthValue = "Basic $base64"

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", $basicAuthValue)
    $headers.Add("Accept", "application/json, text/plain, */*")
    $url = -join("https://",$accountName,".saas.appdynamics.com/controller/auth?action=login")
    try {
        $response = Invoke-WebRequest $url -Method 'GET' -Headers $headers -Body $body -SessionVariable session
        $headers.Add("Cookie", $response.Headers.'Set-Cookie')
    }
    catch {
        $StatusCode = $_.Exception.Response.StatusCode.value__
        return "Error obtaining login headers (Status code $StatusCode)"       
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
function getAppById ($appID, $accountName, $connection) {
    $url = -join("https://",$accountName,".saas.appdynamics.com/controller/rest/applications/",$appID,"?output=JSON")
    try {
        $response = Invoke-WebRequest $url -Method 'GET' -Headers $connection.headers | ConvertFrom-Json
        return $response.name    
    }
    catch {
        $StatusCode = $_.Exception.Response.StatusCode.value__
        return "Error getting app ID (Status code $StatusCode)"
    }
}

# get the ID of an application by its name
function getIdByAppName ($appName, $accountName, $connection) {
    $appNameEncoded = [uri]::EscapeDataString($appName)
    $url = -join("https://",$accountName,".saas.appdynamics.com/controller/rest/applications/",$appNameEncoded,"?output=JSON")
    try {
        $response = Invoke-RestMethod $url -Method 'GET' -Headers $connection.headers
        return $response.id    
    }
    catch {
        $StatusCode = $_.Exception.Response.StatusCode.value__
        return "Error getting app name (Status code $StatusCode)"
    }
}

# get the name of a backend by its ID
function getBackendById ($backendID, $accountName, $connection) {
    $url = -join("https://",$accountName,".saas.appdynamics.com/controller/restui/backendFlowMapUiService/backend/",$backendID,"?time-range=last_12_hours.BEFORE_NOW.-1.-1.60&mapId=-1")
    try {
        $response = Invoke-WebRequest $url -Method 'GET' -WebSession $connection.session -Headers $connection.headers
        return $response.name    
    }
    catch {
        $StatusCode = $_.Exception.Response.StatusCode.value__
        # Write-Host $StatusCode ## DEBUG
        return "Error getting backend name (Status code $StatusCode)"
    }  
}

# return an object with informations of all uninstrumented backends of an application
function getBackendList ($appName, $accountName, $connection) {
    $appID = getIdByAppName -appName $appName -accountName $accountName -connection $connection
    $url = -join("https://",$accountName,".saas.appdynamics.com/controller/rest/applications/",$appID,"/backends?output=JSON")
    try {
        $response = Invoke-RestMethod $url -Method 'GET' -Headers $connection.headers
        return $response
    }
    catch {
        $StatusCode = $_.Exception.Response.StatusCode.value__
        return "Error getting backend list (Status code $StatusCode)"
    }
}

# return an object with informations of all servers hosting an application
function getAppServers ($appName, $accountName, $connection) {
    $appID = getIdByAppName -appName $appName -accountName $accountName -connection $connection

    $url = -join("https://",$accountName,".saas.appdynamics.com/controller/rest/applications/",$appID,"/nodes?output=JSON")
    try {
        $response = Invoke-RestMethod $url -Method 'GET' -Headers $connection.headers
        return $response
    }
    catch {
        $StatusCode = $_.Exception.Response.StatusCode.value__
        return "Error getting server list (Status code $StatusCode)"
    }
}

# get the grid of dependencies of an application with its specific metrics
function getAppGrid ($appName, $accountName, $connection) {
    $appID = getIdByAppName -appName $appName -accountName $accountName -connection $connection

    $url = -join("https://",$accountName,".saas.appdynamics.com/controller/restui/applicationFlowMapUiService/application/",$appID,"?time-range=last_12_hours.BEFORE_NOW.-1.-1.60&mapId=-1&forceFetch=false&baselineId=17148420")
    try {
        $response = Invoke-RestMethod $url -Method 'GET' -WebSession $connection.session -Headers $connection.headers
        if($response.edges -eq $null){
            return "AppDynamics API did not return the full dependency grid. Please try again in a moment"
        }
        else {
            return $response
        }
    }
    catch {
        $StatusCode = $_.Exception.Response.StatusCode.value__
        return "Error getting app dependency grid (Status code $StatusCode)"
    }
}

# list the name of all dependencies of an application (other applications and backends)
function getAppDependencies ($appName, $accountName, $connection) {
    $dependencies = @()
    $grid = getAppGrid -appName $appName -accountName $accountName -connection $connection
    foreach ($edge in $grid.edges) {
        if($edge.targetNodeDefinition.entityType -eq "APPLICATION")
        {
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
function getAppDependenciesWithType ($appName, $accountName, $connection) {
    $dependencies = @()
    $grid = getAppGrid -appName $appName -accountName $accountName -connection $connection
    foreach ($edge in $grid.edges) {
        if($edge.targetNodeDefinition.entityType -eq "APPLICATION")
        {
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
function exportDependenciesCSV ($appName, $accountName, $connection, $outputFilename) {
    $dependencies = getAppDependenciesWithType -appName $appName -accountName $accountName -connection $connection
    if($outputFilename -eq $null)
    {
        $outputFilename = "$appName.csv"
    }    
    foreach ($dependency in $dependencies) {
        # Add-Content -Path $filename -Value "$appName, $dependency" -Force
        Add-Content -Path $outputFilename -Value "$dependency" -Force
    }
}

# export the dependencies of a list of applications (with types) to a file separated by |
function exportListAppDependenciesCSV ($appListFile, $accountName, $connection, $outputFilename) {
    $appList = Get-Content $appListFile
    foreach ($appName in $appList) {
        $dependencies = getAppDependenciesWithType -appName $appName -accountName $accountName -connection $connection

        foreach ($dependency in $dependencies) {
            Add-Content -Path $outputFilename -Value "$appName | $dependency" -Force

        }   
    }
}