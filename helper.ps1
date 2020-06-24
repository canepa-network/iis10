function IIS.BuildConfig 
    param(
        [string]$path
    )
    function Get-STIGViewer {
        param(
            [string]$search,
            [switch]$return_search
        )
        $progressPreference = 'silentlyContinue'
        $STIG_Data = [pscustomobject]@()
        $STIGViewer_URL = "https://www.stigviewer.com"
        $STIGViewer = (Invoke-WebRequest "$STIGViewer_URL/stigs" -SessionVariable token -Verbose:$false).links | Select-Object outerText, href | Where-Object { $_.href -like "/stig/*" } | ForEach-Object {
            [pscustomobject]@{
                name = $_.outerText
                url  = [string]($STIGViewer_URL + $_.href)
            }
        }
    
        $Search_Result = $STIGViewer | Where-Object { $_.name -like "*$search*" }
        if ($return_search) {
            return ($Search_Result | Out-String -Stream)
            exit
        }
    
        foreach ($STIGViewer_Item in $Search_Result) {
            $temp = (Invoke-WebRequest -Verbose:$false ($STIGViewer_Item).url -WebSession $token).links | Select-Object outerText, href | Where-Object { $_.href -like "*/stig/*/finding/*" -or $_.href -like "*/json" }
            $Data = (Invoke-RestMethod -Verbose:$false ([string]($STIGViewer_URL + ($temp | Where-Object { $_.href -like "*/json" }).href)) -WebSession $token).stig
            $refs = $temp | Where-Object { $_.href -notlike "*/json" } | ForEach-Object {
                [psobject]@{
                    name = $_.outerText
                    url  = [string]($STIGViewer_URL + ($_.href).trim())
                }
            }
            foreach ($id in $Data.findings.psobject.properties.name) {
                $STIG_Data += [pscustomobject]@{
                    Title    = "$($STIGViewer_Item.name)"
                    Date     = "$($Data.date)"
                    ID       = $id
                    Severity = $Data.findings."$id".severity
                    Details  = ($refs | Where-Object { $_.name -eq $id }).url
                }
            }
            $progressPreference = 'Continue'
        }
    
        return [psobject]($STIG_Data)
    }    
    # Get-STIGViewer -search "IIS 10.0" -return_search
    # $STIG = Get-STIGViewer -search "IIS 10.0"

    $STIG = Get-STIGViewer -search "IIS 10.0"

    $config = [PSCustomObject]@()
    $config += "[PSCustomObject]@{"
    foreach ($_ in $STIG) {
        $config += "    '$($_.ID)' = @{"
        $config += "        # '$($_.Details)'"
        $config += "        Fix       = [scriptblock] {`n"
        $config += "        }"
        $config += "    }"
    }
    $config += "}"
    $config | Out-File -Encoding 'utf8' "$path\config.ps1"
}
# . ".\config\helper.ps1"
# IIS.BuildConfig

function PerformanceTrigger {
    param(
        [switch]$On,
        [switch]$Off
    )
    if ($Off) {
        $ProgressPreference = 'Continue'
    }
    if ($On) {
        $ProgressPreference = 'SilentlyContinue'
    }
}

function IIS.SetRegistry {
    [cmdletbinding()]
    param(
        [ValidateNotNullOrEmpty()]
        [string[]]$path,
        [string]$type,
        [string]$name,
        [psobject]$value
    )

    if (-not (Test-Path "$path")) {

        # create needed reg path items
        $split_path = $path.split("\")
        foreach ($item in $split_path) {
            $l = $split_path.IndexOf($item)
            if ($l -eq -1) { $l = $split_path.Count }
            $test_path = ($split_path[0..$l]) -join '\'
            if (-not (Test-Path "$test_path")) {
                $null = New-Item "$test_path" -Confirm:$false -Verbose:$false
            }
        }

        # if value set key
        if ($value -like "*") {
            $null = New-ItemProperty -path "$path" -name "$name" -value $value -type $type -Force -Verbose:$false
            Write-Verbose "${path} || $name [$value]"   
        }
    }
    else {
        if ($value -like "*") {
            $test = Get-Item -Path "$path" -EA SilentlyContinue
            if ($test.Property.Contains("$name")) {
                $current_value = Get-ItemPropertyValue -Path "$path" -Name "$name"
                if ($current_value -ne $value) {
                    $null = Set-ItemProperty -path "$path" -name "$name" -value $value -Force -Verbose:$false
                    Write-Verbose "${path} || $name [$value]"   
                }
                else {
                    Write-Verbose "${path} || $name [$value]"   
                }
            }
            else {
                $null = New-ItemProperty -path "$path" -name "$name" -value $value -type $type -Force -Verbose:$false
                Write-Verbose "${path} || $name [$value]" 
            }  
        }
        else {
            Write-Verbose "${path}"
        }
    }
   
}
# IIS.SetRegistry -path "" -name "Enabled" -type "DWord" -value 0 -Verbose

function IIS.Harden {
    # Security Ref: (https://www.hass.de/content/setup-microsoft-windows-or-iis-ssl-perfect-forward-secrecy-and-tls-12)
    # [perfect] DoD Hardening: ACAS 

    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocol"
    $types = ("Server", "Client")

    # Disable Multi-Protocol Unified Hello
    $key = "Multi-Protocol Unified Hello"
    foreach ($i in $types) {
        IIS.SetRegistry -path "$path\$key\$i" -name "Enabled" -type "DWord" -value 0 -Verbose
        IIS.SetRegistry -path "$path\$key\$i" -name "DisabledByDefault" -type "DWord" -value 1 -Verbose
    }

    # Disable PCT 1.0
    $key = "PCT 1.0"
    foreach ($i in $types) {
        IIS.SetRegistry -path "$path\$key\$i" -name "Enabled" -type "DWord" -value 0 -Verbose
        IIS.SetRegistry -path "$path\$key\$i" -name "DisabledByDefault" -type "DWord" -value 1 -Verbose
    }

    # Disable SSL 2.0 (PCI Compliance)
    $key = "SSL 2.0"
    foreach ($i in $types) {
        IIS.SetRegistry -path "$path\$key\$i" -name "Enabled" -type "DWord" -value 0 -Verbose
        IIS.SetRegistry -path "$path\$key\$i" -name "DisabledByDefault" -type "DWord" -value 1 -Verbose
    }

    # NOTE: If you disable SSL 3.0 the you may lock out some people still using
    # Windows XP with IE6/7. Without SSL 3.0 enabled, there is no protocol available
    # for these people to fall back. Safer shopping certifications may require that
    # you disable SSLv3.
    #
    # Disable SSL 3.0 (PCI Compliance) and enable "Poodle" protection
    $key = "SSL 3.0"
    foreach ($i in $types) {
        IIS.SetRegistry -path "$path\$key\$i" -name "Enabled" -type "DWord" -value 0 -Verbose
        IIS.SetRegistry -path "$path\$key\$i" -name "DisabledByDefault" -type "DWord" -value 1 -Verbose
    }

    # Disable TLS 1.0 for client and server SCHANNEL communications
    $key = "TLS 1.0"
    foreach ($i in $types) {
        IIS.SetRegistry -path "$path\$key\$i" -name "Enabled" -type "DWord" -value 0 -Verbose
        IIS.SetRegistry -path "$path\$key\$i" -name "DisabledByDefault" -type "DWord" -value 1 -Verbose
    }

    # Add and Disable TLS 1.1 for client and server SCHANNEL communications
    $key = "TLS 1.1"
    foreach ($i in $types) {
        IIS.SetRegistry -path "$path\$key\$i" -name "Enabled" -type "DWord" -value 0 -Verbose
        IIS.SetRegistry -path "$path\$key\$i" -name "DisabledByDefault" -type "DWord" -value 1 -Verbose
    }

    # Add and Enable TLS 1.2 for client and server SCHANNEL communications
    $key = "TLS 1.2"
    foreach ($i in $types) {
        IIS.SetRegistry -path "$path\$key\$i" -name "Enabled" -type "DWord" -value 1 -Verbose
        IIS.SetRegistry -path "$path\$key\$i" -name "DisabledByDefault" -type "DWord" -value 0 -Verbose
    }

    # Re-create the ciphers key.
    $key = "SSL 2.0"
    foreach ($i in $types) {
        IIS.SetRegistry -path "$path\$key\$i" -name "Enabled" -type "DWord" -value 0 -Verbose
        IIS.SetRegistry -path "$path\$key\$i" -name "DisabledByDefault" -type "DWord" -value 1 -Verbose
    }

    # Disable insecure/weak ciphers.
    $insecureCiphers = @(
        "DES 56/56",
        "NULL",
        "RC2 128/128",
        "RC2 40/128",
        "RC2 56/128",
        "RC4 40/128",
        "RC4 56/128",
        "RC4 64/128",
        "RC4 128/128",
        "Triple DES 168"
    )
    Foreach ($insecureCipher in $insecureCiphers) {
        IIS.SetRegistry -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$insecureCipher" -name "Enabled" -value 0 -type "DWord" -Verbose
    }

    # Enable new secure ciphers.
    # - RC4: It is recommended to disable RC4, but you may lock out WinXP/IE8 if you enforce this. This is a requirement for FIPS 140-2.
    # - 3DES: It is recommended to disable these in near future. This is the last cipher supported by Windows XP.
    # - Windows Vista and before "Triple DES 168" was named "Triple DES 168/168" per https://support.microsoft.com/en-us/kb/245030
    $secureCiphers = @(
        "AES 128/128",
        "AES 256/256"
    )
    Foreach ($secureCipher in $secureCiphers) {
        IIS.SetRegistry -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$secureCipher" -name "Enabled" -value '0xffffffff' -type "DWord" -Verbose
    }

    # Set hashes configuration.
    IIS.SetRegistry -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5" -name "Enabled" -value 0 -type "DWord" -Verbose

    $secureHashes = @(
        "SHA",
        "SHA256",
        "SHA384",
        "SHA512"
    )
    Foreach ($secureHash in $secureHashes) {
        IIS.SetRegistry -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\$secureHash" -name "Enabled" -value '0xffffffff' -type "DWord" -Verbose
    }

    # Set KeyExchangeAlgorithms configuration.
    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms"
    $secureKeyExchangeAlgorithms = @(
        "Diffie-Hellman",
        "ECDH",
        "PKCS"
    )
    Foreach ($secureKeyExchangeAlgorithm in $secureKeyExchangeAlgorithms) {
        IIS.SetRegistry -path "$path\$secureKeyExchangeAlgorithm" -name "Enabled" -value '0xffffffff' -type "DWord" -Verbose
    }

    # Microsoft Security Advisory 3174644 - Updated Support for Diffie-Hellman Key Exchange
    # https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2016/3174644
    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman"
    IIS.SetRegistry -path "$path" -name "ServerMinKeyBitLength" -type "DWord" -value '2048' -Verbose
    IIS.SetRegistry -path "$path" -name "ClientMinKeyBitLength" -type "DWord" -value '2048' -Verbose
    
    # https://support.microsoft.com/en-us/help/3174644/microsoft-security-advisory-updated-support-for-diffie-hellman-key-exc
    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS"
    IIS.SetRegistry -path "$path" -name "ClientMinKeyBitLength" -type "DWord" -value '2048' -Verbose

    # Set cipher suites order as secure as possible (Enables Perfect Forward Secrecy).
    $os = Get-CimInstance -class 'Win32_OperatingSystem' -Verbose:$false
    if ([System.Version]$os.Version -lt [System.Version]"10.0") {
        Write-Host "Use cipher suites order for Windows 2008/2008R2/2012/2012R2."
        $cipherSuitesOrder = @(
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P521",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P384",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P256",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P521",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P384",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P521",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P384",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P256",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P521",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P384",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P521",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P521",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P521",
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P521",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P521",
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P384",
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P521",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P256",
            # Below are the only AEAD ciphers available on Windows 2012R2 and earlier.
            # - RSA certificates need below ciphers, but ECDSA certificates (EV) may not.
            # - We get penalty for not using AEAD suites with RSA certificates.
            "TLS_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_RSA_WITH_AES_256_CBC_SHA256",
            "TLS_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_RSA_WITH_AES_256_CBC_SHA",
            "TLS_RSA_WITH_AES_128_CBC_SHA"
        )
    }
    else {
        $cipherSuitesOrder = @(
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
        )
    }
    $cipherSuitesAsString = [string]::join(",", $cipherSuitesOrder)
    # One user reported this key does not exists on Windows 2012R2. Cannot repro myself on a brand new Windows 2012R2 core machine. Adding this just to be save.
    $path = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" 
    IIS.SetRegistry -path "$path" -name "Functions" -type "String" -value $cipherSuitesAsString -Verbose

    # Exchange Server TLS guidance Part 2: Enabling TLS 1.2 and Identifying Clients Not Using It
    # https://blogs.technet.microsoft.com/exchange/2018/04/02/exchange-server-tls-guidance-part-2-enabling-tls-1-2-and-identifying-clients-not-using-it/
    # New IIS functionality to help identify weak TLS usage
    # https://cloudblogs.microsoft.com/microsoftsecure/2017/09/07/new-iis-functionality-to-help-identify-weak-tls-usage/
    $path = "HKLM:\SOFTWARE\Microsoft\.NETFramework"
    $versions = ("v2.0.50727", "v4.0.30319")
    foreach ($version in $versions) {
        IIS.SetRegistry -path "$path\$version" -name "SystemDefaultTlsVersions" -value 1 -type "DWord" -Verbose
        IIS.SetRegistry -path "$path\$version" -name "SchUseStrongCrypto" -value 1 -type "DWord" -Verbose
    }
    if (Test-Path "HKLM:\SOFTWARE\Wow6432Node") {
        $path = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework"
        foreach ($version in $versions) {
            IIS.SetRegistry -path "$path\$version" -name "SystemDefaultTlsVersions" -value 1 -type "DWord" -Verbose
            IIS.SetRegistry -path "$path\$version" -name "SchUseStrongCrypto" -value 1 -type "DWord" -Verbose
        }
    }

    # DefaultSecureProtocols Value	Decimal value  Protocol enabled
    # 0x00000008                                8  Enable SSL 2.0 by default
    # 0x00000020                               32  Enable SSL 3.0 by default
    # 0x00000080                              128  Enable TLS 1.0 by default
    # 0x00000200                              512  Enable TLS 1.1 by default
    # 0x00000800                             2048  Enable TLS 1.2 by default
    $defaultSecureProtocols = @(
        "512" # Enable TLS 1.1
        "2048"  # Enable TLS 1.2
    )
    $defaultSecureProtocolsSum = ($defaultSecureProtocols | Measure-Object -Sum).Sum

    # Verify if hotfix KB3140245 is installed.
    $file_version_winhttp_dll = (Get-Item $env:windir\System32\winhttp.dll).VersionInfo | ForEach-Object { ("{0}.{1}.{2}.{3}" -f $_.ProductMajorPart, $_.ProductMinorPart, $_.ProductBuildPart, $_.ProductPrivatePart) }
    $file_version_webio_dll = (Get-Item $env:windir\System32\Webio.dll).VersionInfo | ForEach-Object { ("{0}.{1}.{2}.{3}" -f $_.ProductMajorPart, $_.ProductMinorPart, $_.ProductBuildPart, $_.ProductPrivatePart) }
    if ([System.Version]$file_version_winhttp_dll -lt [System.Version]"6.1.7601.23375" -or [System.Version]$file_version_webio_dll -lt [System.Version]"6.1.7601.23375") {
        Write-Error "WinHTTP: Cannot enable TLS 1.2. Please see https://support.microsoft.com/en-us/help/3140245/update-to-enable-tls-1-1-and-tls-1-2-as-a-default-secure-protocols-in for system requirements."
    }
    else {
        $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp"
        IIS.SetRegistry -path "$path" -name "DefaultSecureProtocols" -value $defaultSecureProtocolsSum -type "DWord" -Verbose
        if (Test-Path "HKLM:\SOFTWARE\Wow6432Node") {
            # WinHttp key seems missing in Windows 2019 for unknown reasons.
            $path = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp"
            IIS.SetRegistry -path "$path" -name "DefaultSecureProtocols" -value $defaultSecureProtocolsSum -type "DWord" -Verbose
        }
    }

    $path = ("HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings", "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings")
    foreach ($path in $paths) {
        IIS.SetRegistry -path "$path" -name "SecureProtocols" -value $defaultSecureProtocolsSum -type "DWord" -Verbose
    }

    # Set no first run IE [for powershell 'invoke-webrequest']
    IIS.SetRegistry -path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main" -name "DisableFirstRunCustomize" -Value 1 -type "DWord"
}
# IIS.Harden

############
function IIS.Partition {
    [cmdletbinding()]
    param(
        [ValidateNotNullOrEmpty()]
        [char]$DriveLetter,
        [ValidateNotNullOrEmpty()]
        [int]$GBSize = 10,
        [ValidateNotNullOrEmpty()]
        [string]$DriveLabel = 'IIS'
    )

    # Make Room for new Partition
    $null = Get-PSDrive
    $GetVolumes = Get-Volume -Verbose:$false
    if (-not ($GetVolumes.DriveLetter -contains $DriveLetter)) {

        # select os par from initial test
        $OS_Partition = $GetVolumes | Where-Object { $_.DriveLetter -eq ($env:HOMEDRIVE[0]) } | Get-Partition
    
        # Clean up unallocated space
        if ($OS_Partition.Size -lt ($OS_Partition | Get-PartitionSupportedSize -OutVariable 'OS_ParSize').sizemax) {
            $OS_Partition | Resize-Partition -Size ($OS_ParSize).sizemax -Confirm:$false
            $null = Get-PSDrive
            $OS_Partition = $GetVolumes | Where-Object { $_.DriveLetter -eq ($env:HOMEDRIVE[0]) } | Get-Partition
        }

        # collect needed variables
        $reqvalue = [Int64][scriptblock]::Create("$GBSize" + "Gb").Invoke()[0]
        $OS_Partition = [psobject]@{
            'DiskNumber'      = $OS_Partition.DiskNumber
            'PartitionNumber' = $OS_Partition.PartitionNumber
            'RequestedSize'   = $reqvalue
            'ResizeValue'     = ($OS_Partition.Size - $reqvalue)
        }

        # Make new partition
        Resize-Partition -DiskNumber $OS_Partition.DiskNumber -PartitionNumber $OS_Partition.PartitionNumber -Size $OS_Partition.ResizeValue -Confirm:$false

        # Format New Partition
        $IIS_Partition = New-Partition -DiskNumber $OS_Partition.DiskNumber -Size $OS_Partition.RequestedSize -AssignDriveLetter:$False `
        | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel $DriveLabel -confirm:$False -Force | Get-Partition
        $IIS_Partition | Set-Partition -NewDriveLetter $DriveLetter -Confirm:$False -Verbose:$False
        Start-Sleep -Milliseconds 400
        ((New-Object -ComObject Shell.Application).Windows() | Where-Object { $_.LocationURL -eq "file:///${DriveLetter}:/" }).quit()
        # Wait for drive-path setup
        Do {
            $test = $False
            if (Test-Path "${DriveLetter}:\") {
                $test = $true
            }
            else {
                $null = Get-PSDrive
                Start-Sleep -Seconds 1
            }
        }until($test -eq $true)
    }

}
# IIS.Partition -DriveLetter 'x' -DriveLabel 'IIS' -GBSize 10

############
function IIS.Move {
    [cmdletbinding()]
    param(
        [ValidateNotNullOrEmpty()]
        [char]$DriveLetter
    )
    #// Create variables
    $OldPath = "%SystemDrive%\inetpub"
    $NewPath = "${DriveLetter}:\inetpub"

    #// Check new drive actually exists
    if (!(Test-Path "${DriveLetter}:\")) {
        Exit
    }

    #// Check IIS Installed
    if (!(Test-Path ("$env:SystemDrive\inetpub"))) {
        Exit
    }

    #// stop services
    & iisreset /stop | Out-Null
    Start-Sleep -Seconds 2

    #// move inetpub directory
    & Robocopy "$env:SystemDrive\inetpub" "$NewPath" *.* /MOVE /S /E /COPYALL /R:0 /W:0 | Out-Null

    #// modify reg
    IIS.SetRegistry -Path "HKLM:\SOFTWARE\Microsoft\InetStp" -Name "PathWWWRoot" -Value "$NewPath\wwwroot" -type 'ExpandString' -Verbose
    IIS.SetRegistry -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\InetStp" -Name "PathWWWRoot" -Value "$NewPath\wwwroot" -type 'ExpandString' -Verbose
    IIS.SetRegistry -Path "HKLM:\System\CurrentControlSet\Services\WAS\Parameters" -Name "ConfigIsolationPath" -Value "$NewPath\temp\appPools" -type 'String' -Verbose

    #// Backup and modify applicationHost.config file
    Copy-Item "$env:SystemDrive\Windows\System32\inetsrv\config\applicationHost.config" "$env:SystemDrive\Windows\System32\inetsrv\config\applicationHost.config.bak"
    Start-Sleep 2

    #// Replace "%SystemDrive%\inetpub" with $NewDrive":\inetpub"
    (Get-Content "$env:SystemDrive\Windows\System32\inetsrv\config\applicationHost.config").replace("$OldPath", "$NewPath") `
    | Set-Content "$env:SystemDrive\Windows\System32\inetsrv\config\applicationHost.config"

    #// Update IIS Config
    & C:\Windows\system32\inetsrv\appcmd set config -section:system.applicationhost/configHistory -path:"$NewPath\history" | Out-Null

    #// Start services
    & iisreset /start | Out-Null
}

# IIS.Move -DriveLetter 'x'

############
function Test-Credentials {
    [cmdletbinding()]
    Param()
    If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {  
        Write-Error "You are not currently running this under an Administrator account! `nThere is potential that this command could fail if not running under an Administrator account."  
        Break
    } 
}

###########
# IIS Features List
$IIS_Features = [PSObject]@{
    enabled = @(
        'IIS-ApplicationDevelopment',
        'IIS-ApplicationInit',
        'IIS-ASPNET45',
        'IIS-CertProvider',
        'IIS-CommonHttpFeatures',
        'IIS-CustomLogging',
        'IIS-DefaultDocument',
        'IIS-HealthAndDiagnostics',
        'IIS-HttpCompressionDynamic',
        'IIS-HttpCompressionStatic',
        'IIS-HttpErrors',
        'IIS-HttpLogging',
        'IIS-HttpRedirect',
        'IIS-HttpTracing',
        'IIS-IPSecurity',
        'IIS-ISAPIExtensions',
        'IIS-ISAPIFilter',
        'IIS-LoggingLibraries',
        'IIS-ManagementConsole',
        'IIS-ManagementScriptingTools',
        'IIS-NetFxExtensibility45',
        'IIS-Performance',
        'IIS-RequestFiltering',
        'IIS-RequestMonitor',
        'IIS-Security',
        'IIS-ServerSideIncludes',
        'IIS-StaticContent',
        'IIS-URLAuthorization',
        'IIS-WebServer',
        'IIS-WebServerManagementTools',
        'IIS-WebServerRole',
        'IIS-WebSockets',
        'IIS-WindowsAuthentication'
    )
}

function IIS.SetFeatures {
    [cmdletbinding()]
    param(
        [string[]]
        $EnabledFeatures = $IIS_Features.enabled
    )

    # run
    $Setup_Log = [string[]]@()
    $Setup_Log += (Enable-WindowsOptionalFeature -Online -NoRestart -All -FeatureName $EnabledFeatures).RestartNeeded
    $Setup_Log += (Disable-WindowsOptionalFeature -Online -NoRestart -FeatureName (
            Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -like "IIS*" -and $_.State -ne "Enabled" }).FeatureName ).RestartNeeded
    
    # return
    if ($Setup_Log.RestartNeeded -contains $true) {
        return [psobject]@{'rebootrequired' = $true }
    }
    else {
        return [psobject]@{'rebootrequired' = $false }
    }
}
#IIS.SetFeatures -EnabledFeatures $IIS_Features.enabled

##########
function IIS.STIG {
    param(
        [ValidateNotNullOrEmpty()]
        [string]$Path,
        [psobject]$Value,
        [ValidateSet("eq", "gt", "lt", "ge", "le", "ne", "like", "notlike", "contains", "notcontains")]
        [string]$CompArg = "eq",
        [switch]$Get,
        [switch]$Test,
        [switch]$Set
    )

    function Lock-Property {
        param(
            [string]$Path
        )

        if ($Path -like "*/add*") {
            try {
                Add-WebConfigurationLock -pspath 'MACHINE/WEBROOT/APPHOST' -filter "$Path" -type general -Force
            }
            catch {
                Add-WebConfigurationLock -pspath 'MACHINE/WEBROOT' -filter "$Path" -type general -Force
            }
        }
        else {
            try {
                Add-WebConfigurationLock -pspath 'MACHINE/WEBROOT' -filter "$Path" -type inclusive -Force
            }
            catch {
                Add-WebConfigurationLock -pspath 'MACHINE/WEBROOT/APPHOST' -filter "$Path" -type inclusive -Force
            }
        }
    }

    # Build
    $SectionPaths = (
        'system.web/anonymousIdentification',
        'system.web/authentication',
        'system.web/authorization',
        'system.web/browserCaps',
        'system.web/clientTarget',
        'system.web/compilation',
        'system.web/customErrors',
        'system.web/deviceFilters',
        'system.web/globalization',
        'system.web/healthMonitoring',
        'system.web/hostingEnvironment',
        'system.web/httpCookies',
        'system.web/httpHandlers',
        'system.web/httpModules',
        'system.web/httpRuntime',
        'system.web/identity',
        'system.web/machineKey',
        'system.web/mobileControls',
        'system.web/pages',
        'system.web/protocols',
        'system.web/securityPolicy',
        'system.web/sessionPageState',
        'system.web/sessionState',
        'system.web/siteMap',
        'system.web/trace',
        'system.web/trust',
        'system.web/urlMappings',
        'system.web/webControls',
        'system.web/webParts',
        'system.web/webServices',
        'system.web/xhtmlConformance',
        'system.web/caching/cache',
        'system.web/caching/outputCache',
        'system.web/caching/outputCacheSettings',
        'system.web/caching/sqlCacheDependency',
        'system.web/fullTrustAssemblies',
        'system.web/partialTrustVisibleAssemblies',
        'system.applicationHost/sites',
        'system.ftpServer/caching',
        'system.applicationHost/sites',
        'system.ftpServer/log',
        'system.ftpServer/firewallSupport',
        'system.ftpServer/providerDefinitions',
        'system.ftpServer/security/authorization',
        'system.ftpServer/security/ipSecurity',
        'system.ftpServer/security/requestFiltering',
        'system.ftpServer/security/authentication',
        'system.ftpServer/caching',
        'system.ftpServer/serverRuntime',
        'appSettings',
        'configProtectedData',
        'connectionStrings',
        'system.codedom',
        'system.data',
        'system.diagnostics',
        'system.windows.forms',
        'system.net/authenticationModules',
        'system.net/connectionManagement',
        'system.net/defaultProxy',
        'system.net/requestCaching',
        'system.net/settings',
        'system.net/webRequestModules',
        'system.net/mailSettings/smtp',
        'system.transactions/defaultSettings',
        'system.transactions/machineSettings',
        'system.web/deployment',
        'system.web/membership',
        'system.web/processModel',
        'system.web/profile',
        'system.web/roleManager',
        'system.xml.serialization/dateTimeSerialization',
        'system.xml.serialization/schemaImporterExtensions',
        'system.xml.serialization/xmlSerializer',
        'system.applicationHost/applicationPools',
        'system.applicationHost/configHistory',
        'system.applicationHost/customMetadata',
        'system.applicationHost/listenerAdapters',
        'system.applicationHost/log',
        'system.applicationHost/serviceAutoStartProviders',
        'system.applicationHost/sites',
        'system.applicationHost/webLimits',
        'system.webServer/asp',
        'system.webServer/caching',
        'system.webServer/cgi',
        'system.webServer/defaultDocument',
        'system.webServer/directoryBrowse',
        'system.webServer/fastCgi',
        'system.webServer/globalModules',
        'system.webServer/handlers',
        'system.webServer/httpCompression',
        'system.webServer/httpErrors',
        'system.webServer/httpLogging',
        'system.webServer/httpProtocol',
        'system.webServer/httpRedirect',
        'system.webServer/httpTracing',
        'system.webServer/isapiFilters',
        'system.webServer/management/authentication',
        'system.webServer/management/authorization',
        'system.webServer/management/trustedProviders',
        'system.webServer/modules',
        'system.webServer/applicationInitialization',
        'system.webServer/odbcLogging',
        'system.webServer/security/access',
        'system.webServer/security/applicationDependencies',
        'system.webServer/security/authentication/anonymousAuthentication',
        'system.webServer/security/authentication/basicAuthentication',
        'system.webServer/security/authentication/clientCertificateMappingAuthentication',
        'system.webServer/security/authentication/digestAuthentication',
        'system.webServer/security/authentication/iisClientCertificateMappingAuthentication',
        'system.webServer/security/authentication/windowsAuthentication',
        'system.webServer/security/authorization',
        'system.webServer/security/ipSecurity',
        'system.webServer/security/dynamicIpSecurity',
        'system.webServer/security/isapiCgiRestriction',
        'system.webServer/security/requestFiltering',
        'system.webServer/serverRuntime',
        'system.webServer/serverSideInclude',
        'system.webServer/staticContent',
        'system.webServer/tracing/traceFailedRequests',
        'system.webServer/tracing/traceProviderDefinitions',
        'system.webServer/urlCompression',
        'system.webServer/validation',
        'system.webServer/webSocket',
        'configPaths',
        'moduleProviders',
        'modules',
        'administratorsProviders',
        'administrators',
        'configurationRedirection',
        'system.applicationHost/sites',
        'system.applicationHost/applicationPools',
        'system.webServer/webdav/globalSettings',
        'system.webServer/webdav/authoring',
        'system.webServer/webdav/authoringRules'
    )
    $AddC = $false
    $AddI = $false
    Reset-IISServerManager -Confirm:$false
    $SectionPath = $SectionPaths | Where-Object -FilterScript { "$Path" -like "${_}*" } | Select-Object -First 1
    $SP = ($Path).split("/") | Where-Object -FilterScript { ($SectionPath -split "/") -notcontains "$_" }
    $Data = Get-IISConfigSection -SectionPath $SectionPath
    $Property = $SP | Select-Object -Last 1
    $Drill = $SP | Where-Object -FilterScript { "$_" -ne "$Property" }
    foreach ($i in $Drill) {
        if ($Data.ChildElements.ElementTagName -contains $i) {
            $Data = $Data | Get-IISConfigElement -ChildElementName $i
        }
    }
    $Mid = $Drill -join '/'

    # Get
    $Get_Value = try {
        $Data | Get-IISConfigAttributeValue -AttributeName $Property

    }
    catch {
        $AddC = $true
        (($Data | Get-IISConfigCollection) | ForEach-Object {
                $t = @()
                foreach ($a in $_.Attributes) {
                    $t += [psobject]@{
                        $a.Name = $a.Value
                    }
                }
                $t
            })."$Property"
    }
    if ($Get) {
        return ($Get_Value -join ', ')
    }

    # Test
    if ($Test -or $Set) {
        if ($Value.count -gt 1) {
            if ($Value."$Property".count -ge 1) {
                $Test0 = $Value."$Property"
            }
            else {
                $Test0 = $Value
            }
        }
        else {
            $Test0 = $Value
        }
        if ($Get_Value -like "*,*") {

            $Get_Value0 = ($Get_Value -split ',')
            $Test0 = ($Value -split ',')
            $AddI = $true
        }
        else {
            $Get_Value0 = $Get_Value
        }

        $Test_Value = switch ($CompArg) {
            "eq" { ($Get_Value0 -eq $Test0) }
            "ne" { ($Get_Value0 -ne $Test0) }
            "like" { ($Get_Value0 -like "*$Test0*") }
            "notlike" { ($Get_Value0 -notlike $Test0) }
            "gt" { ($Get_Value0 -gt $Test0) }
            "lt" { ($Get_Value0 -lt $Test0) }
            "ge" { ($Get_Value0 -ge $Test0) }
            "le" { ($Get_Value0 -le $Test0) }
            "contains" { 
                $t = foreach ($_ in $Test0) { ($Get_Value0 -contains $_) }
                if ($t -contains $false) { $false }else { $true }
            }
            "notcontains" { 
                $t = foreach ($_ in $Test0) { ($Get_Value0 -notcontains $_) } 
                if ($t -contains $false) { $false }else { $true }
            }
        }
    }
    if ($Test) {
        return $Test_Value
    }

    # Set
    if ($Set) {
        if (! $Test_Value) {
            if ($Mid) {
                $Filter = "$SectionPath/$Mid"
            }
            else {
                $Filter = "$SectionPath"
            }
            if ($AddC -eq $true) {
                Add-WebConfigurationProperty -filter $Filter -name "." -value $Value
                $Return = ($Value."$Property" -join ',')
            }
            elseif ($AddI -eq $true) {
                Set-WebConfigurationProperty -filter $Filter -name "$Property" -value "$Get_Value,$Value"
                Lock-Property -Path "$Filter/@$Property"
                $Return = ($Value -join ',')
            }
            else {
                Set-WebConfigurationProperty -filter "$Filter" -Name "$Property" -Value $Value
                Lock-Property -Path "$Filter/@$Property"
                $Return = $Value
            }
            (Get-IISServerManager).CommitChanges()
            return "$Property $(if($AddC){'+'}else{'>'}) $($Return | Out-String -Stream)"
        }
        else {
            if (! $AddC) {
                Lock-Property -Path "$Filter/@$Property"
            }
            else {
                $Value = $Value."$Property"
            }
            return "$Property $(if($AddC){'[contains]'}else{'='}) $(($Value -join ',') | Out-String -Stream)"
        }
    }

}
# IIS.STIG -SectionPath system.web -AttributeName compressionEnabled -Value $false -Lookup


function IIS.NTFS {
    param(
        [string]$Path,
        [string]$Sddl,
        [switch]$Get,
        [switch]$Test,
        [switch]$Set
    )

    $Get_Value = (Get-Acl "$Path").Sddl
    if ($Get) {
        return $Get_Value
    }

    $Test_Value = if ($Get_Value -eq $Sddl) { $true }else { $false }
    if ($Test) {
        return $Test_Value
    }

    if ($Set) {
        if (! $Test_Value) {
            $acl = Get-Acl -Path "$Path"
            $acl.SetSecurityDescriptorSddlForm($Sddl)
            Set-Acl -Path "$Path" -AclObject $acl
            return "$Path > [$Sddl]"
        }
        else {
            return "$Path = '$Sddl'"
        }
    }
}
# 1. Set Permissions
# 2. Collect Value: IIS.NTFS -Path X:\inetpub\logs -Get
# 3. Collect Value: IIS.NTFS -Path X:\inetpub\logs -Sddl $Value -Test
# 4. Collect Value: IIS.NTFS -Path X:\inetpub\logs -Sddl $Value -Set
