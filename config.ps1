function Update-Registry() {
    [cmdletbinding()]
    param(
        [ValidateNotNullOrEmpty()]
        [string[]]$path,
        [string]$type,
        [string]$name,
        [psobject]$value
    )

    <#
    switch ($path) {
        "hklm:\*" { [switch]$htlm }
        "default" { [switch]$default }
    }

    # HKLM
    if ($default) {
        Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers"
        $Reg_Root = (Get-Item "HKLM:\").OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers", $true)
        $Reg_Root.GetSubKeyNames()

        # key verify

        # value verify
        $Current_Keys = (Get-Item "HKLM:\").OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers", $true).GetSubKeyNames()
        if ($Current_Keys -notcontains "$name") {

        }
        .GetValueNa("DES 56/56\Enabled")
        $key = (Get-Item HKLM:\).OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers", $true).CreateSubKey($insecureCipher)
        $key.SetValue("Enabled", 0, "DWord")
        [Microsoft.PowerShell.Core\Registry]::
        $Reg_Root.close()
    }
    #>

    # All Else
    # if ($default) {
    foreach ($reg_path in $path) {
        if (-not (Test-Path "$reg_path")) {
            Write-Verbose "(missing) $reg_path"
            # create needed reg path items
            $split_path = (Convert-Path (Get-ItemProperty "$reg_path").PSPath).split("\")
            $split_path[0] = 'Microsoft.PowerShell.Core\Registry::' + $split_path[0]
            foreach ($item in $split_path) {
                $l = $split_path.IndexOf($item)
                if ($l -eq -1) { $l = $split_path.Count }
                $test_path = ($split_path[0..$l]) -join '\'
                if (-not (Test-Path "$test_path")) {
                    New-Item "$test_path" -Force -Verbose:$false
                    Write-Verbose "(added) $test_path"
                }
            }

            if (($value -ne "") -or (-not $value)) {
                if ((Get-ItemPropertyValue -Path "$reg_path" -Name "$name") -ne $value) {
                    New-ItemProperty -path "$reg_path" -name "$name" -value $value -PropertyType $type -Force -Verbose:$false
                    Write-Verbose "($type) $name [Null >> $value]"   
                }
            }
        }
        else {
            Write-Verbose "(present) $reg_path"
            if ( ($value -ne "") -or (-not $value) ) {
                if ((Get-ItemPropertyValue -Path "$reg_path" -Name "$name" -OutVariable 'current_value') -ne $value) {
                    New-ItemProperty -path "$reg_path" -name "$name" -value $value -PropertyType $type -Force -Verbose:$false
                    Write-Verbose "($type) $name [$current_value >> $value]"   
                }
                else {
                    Write-Verbose "($type) $name [$current_value = $value]"   
                }
            }
        }
    }
    #}
}

function Update-SSL () {
    # Security Ref: (https://www.hass.de/content/setup-microsoft-windows-or-iis-ssl-perfect-forward-secrecy-and-tls-12)
    # [perfect] DoD Hardening: ACAS 

    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocol"
    $types = ("Server", "Client")

    # Disable Multi-Protocol Unified Hello
    $key = "Multi-Protocol Unified Hello"
    foreach ($i in $types) {
        Update-Registry -path "$path\$key\$i" -name "Enabled" -type "DWord" -value 0 -Verbose
        Update-Registry -path "$path\$key\$i" -name "DisabledByDefault" -type "DWord" -value 1 -Verbose
    }

    # Disable PCT 1.0
    $key = "PCT 1.0"
    foreach ($i in $types) {
        Update-Registry -path "$path\$key\$i" -name "Enabled" -type "DWord" -value 0 -Verbose
        Update-Registry -path "$path\$key\$i" -name "DisabledByDefault" -type "DWord" -value 1 -Verbose
    }

    # Disable SSL 2.0 (PCI Compliance)
    $key = "SSL 2.0"
    foreach ($i in $types) {
        Update-Registry -path "$path\$key\$i" -name "Enabled" -type "DWord" -value 0 -Verbose
        Update-Registry -path "$path\$key\$i" -name "DisabledByDefault" -type "DWord" -value 1 -Verbose
    }

    # NOTE: If you disable SSL 3.0 the you may lock out some people still using
    # Windows XP with IE6/7. Without SSL 3.0 enabled, there is no protocol available
    # for these people to fall back. Safer shopping certifications may require that
    # you disable SSLv3.
    #
    # Disable SSL 3.0 (PCI Compliance) and enable "Poodle" protection
    $key = "SSL 3.0"
    foreach ($i in $types) {
        Update-Registry -path "$path\$key\$i" -name "Enabled" -type "DWord" -value 0 -Verbose
        Update-Registry -path "$path\$key\$i" -name "DisabledByDefault" -type "DWord" -value 1 -Verbose
    }

    # Disable TLS 1.0 for client and server SCHANNEL communications
    $key = "TLS 1.0"
    foreach ($i in $types) {
        Update-Registry -path "$path\$key\$i" -name "Enabled" -type "DWord" -value 0 -Verbose
        Update-Registry -path "$path\$key\$i" -name "DisabledByDefault" -type "DWord" -value 1 -Verbose
    }

    # Add and Disable TLS 1.1 for client and server SCHANNEL communications
    $key = "TLS 1.1"
    foreach ($i in $types) {
        Update-Registry -path "$path\$key\$i" -name "Enabled" -type "DWord" -value 0 -Verbose
        Update-Registry -path "$path\$key\$i" -name "DisabledByDefault" -type "DWord" -value 1 -Verbose
    }

    # Add and Enable TLS 1.2 for client and server SCHANNEL communications
    $key = "TLS 1.2"
    foreach ($i in $types) {
        Update-Registry -path "$path\$key\$i" -name "Enabled" -type "DWord" -value 1 -Verbose
        Update-Registry -path "$path\$key\$i" -name "DisabledByDefault" -type "DWord" -value 0 -Verbose
    }

    # Re-create the ciphers key.
    $key = "SSL 2.0"
    foreach ($i in $types) {
        Update-Registry -path "$path\$key\$i" -name "Enabled" -type "DWord" -value 0 -Verbose
        Update-Registry -path "$path\$key\$i" -name "DisabledByDefault" -type "DWord" -value 1 -Verbose
    }

    Update-Registry -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers" -Verbose

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
        Update-Registry -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$insecureCipher" -name "Enabled" -value 0 -type "DWord" -Verbose
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
        Update-Registry -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$secureCipher" -name "Enabled" -value 0 -type "DWord" -Verbose
    }

    # Set hashes configuration.
    Update-Registry -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5" -name "Enabled" -value 0 -type "DWord" -Verbose

    $secureHashes = @(
        "SHA",
        "SHA256",
        "SHA384",
        "SHA512"
    )
    Foreach ($secureHash in $secureHashes) {
        Update-Registry -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\$secureHash" -name "Enabled" -value 0 -type "DWord" -Verbose
    }

    # Set KeyExchangeAlgorithms configuration.
    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms"
    $secureKeyExchangeAlgorithms = @(
        "Diffie-Hellman",
        "ECDH",
        "PKCS"
    )
    Foreach ($secureKeyExchangeAlgorithm in $secureKeyExchangeAlgorithms) {
        Update-Registry -path "$path\$secureKeyExchangeAlgorithm" -name "Enabled" -value 0 -type "DWord" -Verbose
    }

    # Microsoft Security Advisory 3174644 - Updated Support for Diffie-Hellman Key Exchange
    # https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2016/3174644
    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman"
    Update-Registry -path "$path" -name "ServerMinKeyBitLength" -type "DWord" -value 2048 -Verbose
    Update-Registry -path "$path" -name "ClientMinKeyBitLength" -type "DWord" -value 2048 -Verbose
    
    # https://support.microsoft.com/en-us/help/3174644/microsoft-security-advisory-updated-support-for-diffie-hellman-key-exc
    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS"
    Update-Registry -path "$path" -name "ClientMinKeyBitLength" -type "DWord" -value 2048 -Verbose

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
        Write-Host "Use cipher suites order for Windows 10/2016 and later."
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
    Update-Registry -path "$path" -name "Functions" -type "String" -value $cipherSuitesAsString -Verbose

    # Exchange Server TLS guidance Part 2: Enabling TLS 1.2 and Identifying Clients Not Using It
    # https://blogs.technet.microsoft.com/exchange/2018/04/02/exchange-server-tls-guidance-part-2-enabling-tls-1-2-and-identifying-clients-not-using-it/
    # New IIS functionality to help identify weak TLS usage
    # https://cloudblogs.microsoft.com/microsoftsecure/2017/09/07/new-iis-functionality-to-help-identify-weak-tls-usage/
    $path = "HKLM:\SOFTWARE\Microsoft\.NETFramework"
    $versions = ("v2.0.50727", "v4.0.30319")
    foreach ($version in $versions) {
        Update-Registry -path "$path\$version" -name "SystemDefaultTlsVersions" -value 1 -PropertyType "DWord" -Force | Out-Null
        Update-Registry -path "$path\$version" -name "SchUseStrongCrypto" -value 1 -PropertyType "DWord" -Force | Out-Null
    }
    if (Test-Path "HKLM:\SOFTWARE\Wow6432Node") {
        $path = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework"
        foreach ($version in $versions) {
            Update-Registry -path "$path\$version" -name "SystemDefaultTlsVersions" -value 1 -PropertyType "DWord" -Force | Out-Null
            Update-Registry -path "$path\$version" -name "SchUseStrongCrypto" -value 1 -PropertyType "DWord" -Force | Out-Null
        }
    }

    # DefaultSecureProtocols Value	Decimal value  Protocol enabled
    # 0x00000008                                8  Enable SSL 2.0 by default
    # 0x00000020                               32  Enable SSL 3.0 by default
    # 0x00000080                              128  Enable TLS 1.0 by default
    # 0x00000200                              512  Enable TLS 1.1 by default
    # 0x00000800                             2048  Enable TLS 1.2 by default
    $defaultSecureProtocols = @(
        "2048"  # TLS 1.2
    )
    $defaultSecureProtocolsSum = ($defaultSecureProtocols | Measure-Object -Sum).Sum

    # Update to enable TLS 1.2 as a default secure protocols in WinHTTP in Windows
    # https://support.microsoft.com/en-us/help/3140245/update-to-enable-tls-1-1-and-tls-1-2-as-a-default-secure-protocols-in

    # Verify if hotfix KB3140245 is installed.
    $file_version_winhttp_dll = (Get-Item $env:windir\System32\winhttp.dll).VersionInfo | ForEach-Object { ("{0}.{1}.{2}.{3}" -f $_.ProductMajorPart, $_.ProductMinorPart, $_.ProductBuildPart, $_.ProductPrivatePart) }
    $file_version_webio_dll = (Get-Item $env:windir\System32\Webio.dll).VersionInfo | ForEach-Object { ("{0}.{1}.{2}.{3}" -f $_.ProductMajorPart, $_.ProductMinorPart, $_.ProductBuildPart, $_.ProductPrivatePart) }
    if ([System.Version]$file_version_winhttp_dll -lt [System.Version]"6.1.7601.23375" -or [System.Version]$file_version_webio_dll -lt [System.Version]"6.1.7601.23375") {
        Write-Error "WinHTTP: Cannot enable TLS 1.2. Please see https://support.microsoft.com/en-us/help/3140245/update-to-enable-tls-1-1-and-tls-1-2-as-a-default-secure-protocols-in for system requirements."
    }
    else {
        $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp"
        Update-Registry -path "$path" -name "DefaultSecureProtocols" -value $defaultSecureProtocolsSum -PropertyType "DWord" -Verbose
        if (Test-Path "HKLM:\SOFTWARE\Wow6432Node") {
            # WinHttp key seems missing in Windows 2019 for unknown reasons.
            $path = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp"
            Update-Registry -path "$path" -name "DefaultSecureProtocols" -value $defaultSecureProtocolsSum -PropertyType "DWord" -Verbose
        }
    }

    $path = ("HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings", "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings")
    foreach ($path in $paths) {
        Update-Registry -path "$path" -name "SecureProtocols" -value $defaultSecureProtocolsSum -PropertyType "DWord" -Verbose
    }
}

function New-Partition () {
    [cmdletbinding()]
    param(
        [char]$letter,
        [int]$size_in_gb
    )

    # Make Room for new Partition
    $Req_Size = ([int64][scriptblock]::Create("$size_in_gb" + "Gb").Invoke()[0]).ToString()
    $Boot_Par = Get-Partition | Where-Object -FilterScript { $_.IsBoot -eq $true }
    Expand-Disk -Partition $Boot_Par.DiskNumber # expands target disk (for any possible system errors/re-runs)
    if (-not ( $Par.Size -eq $Req_Size ) ) {
        Resize-Partition -DiskNumber $Boot_Par.DiskNumber -PartitionNumber $Boot_Par.PartitionNumber -Size $Req_Size -Confirm:$false
    }

    # Format New Partition
    $NewPar = New-Partition -DiskNumber $Boot_Par.DiskNumber -UseMaximumSize -AssignDriveLetter:$False -EA SilentlyContinue -ErrorVariable skip | Format-Volume -FileSystem "NTFS" -NewFileSystemLabel "iis" -confirm:$False
    if (-not $skip) {
        Set-Partition -DiskNumber $Boot_Par.DiskNumber -PartitionNumber $NewPar.PartitionNumber -NewDriveLetter $letter -EA SilentlyContinue -Verbose:$False

        # Wait for drive-path setup
        Do {
            $test = $False
            if (Test-Path "${letter}:\") {
                $test = $true
            }
            else {
                $null = Get-PSDrive
                Start-Sleep -Seconds 1
            }
        }until($test -eq $true)
    }
}

function Expand-Disk () {
    [cmdletbinding()]
    param(
        [cmdletbinding()]
        [int]$DiskNumber
    )

    $Partition

    # Check if the disk in context is a Boot and System disk
    if ((Get-Disk -Number $Partition.number).IsBoot -And (Get-Disk -Number $Partition.number).IsSystem) {
        # Get the drive letter assigned to the disk partition where OS is installed
        $driveLetter = (Get-Partition -DiskNumber $Partition.Number | Where-Object { $_.DriveLetter }).DriveLetter

        # Get Partition Number of the OS partition on the Disk
        $partitionNum = (Get-Partition -DriveLetter $driveLetter).PartitionNumber

        # Get the available unallocated disk space size
        $unallocatedDiskSize = (Get-Disk -Number $Partition.number).LargestFreeExtent

        # Get the max allowed size for the OS Partition on the disk
        $allowedSize = (Get-PartitionSupportedSize -DiskNumber $Partition.Number -PartitionNumber $partitionNum).SizeMax

        if ($unallocatedDiskSize -gt 0 -And $unallocatedDiskSize -le $allowedSize) {
            $totalDiskSize = $allowedSize
            
            # Resize the OS Partition to Include the entire Unallocated disk space
            Resize-Partition -DriveLetter C -Size $totalDiskSize -Confirm:$false
        }
        else {
            return $false
        }
    }   
    
}

function Move-IIS () {
    [cmdletbinding()]
    param(
        [char]$drive
    )
    #// Create variables
    [string]$OldPath = "%SystemDrive%\inetpub"
    [string]$NewPath = "${drive}:\inetpub"

    #// Check new drive actually exists
    if (!(Test-Path "$NewPath")) {
        Exit
    }

    #// Check IIS Installed
    if (!(Test-Path (([string](Get-Location).Drive.Name) + ":\inetpub"))) {
        Exit
    }

    #// stop services
    & iisreset /stop | Out-Null
    Start-Sleep -Seconds 2

    #// move inetpub directory
    & Robocopy C:\inetpub $NewPath *.* /MOVE /S /E /COPYALL /R:0 /W:0 | Out-Null

    #// modify reg
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\InetStp" -Name "PathWWWRoot" -Value "$NewPath\wwwroot" -PropertyType ExpandString -Force | Out-Null
    New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\WAS\Parameters" -Name "ConfigIsolationPath" -Value "$NewPath\temp\appPools" -PropertyType String -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\InetStp" -Name "PathWWWRoot" -Value "$NewPath\wwwroot" -PropertyType ExpandString -Force | Out-Null

    #// Backup and modify applicationHost.config file
    Copy-Item "C:\Windows\System32\inetsrv\config\applicationHost.config" "C:\Windows\System32\inetsrv\config\applicationHost.config.bak"
    Start-Sleep 5

    #// Replace "%SystemDrive%\inetpub" with $NewDrive":\inetpub"
    (Get-Content "C:\Windows\System32\inetsrv\config\applicationHost.config").replace("$OldPath", "$NewPath") | Set-Content "C:\Windows\System32\inetsrv\config\applicationHost.config"

    #// Update IIS Config
    & C:\Windows\system32\inetsrv\appcmd set config -section:system.applicationhost/configHistory -path:$NewPath\history | Out-Null

    #// Start services
    & iisreset /start | Out-Null
}

New-Variable 'iis-features' -Value (
    # (Get-WindowsOptionalFeature -Online | Where-Object {$_.FeatureName -like "IIS*"}).FeatureName | sort | foreach $_ {"'$($_)',"}
    'IIS-ApplicationInit',
    'IIS-ASP',
    #'IIS-ASPNET',
    'IIS-ASPNET45',
    'IIS-BasicAuthentication',
    'IIS-CertProvider',
    #'IIS-CGI',
    #'IIS-ClientCertificateMappingAuthentication',
    'IIS-CommonHttpFeatures',
    'IIS-CustomLogging',
    'IIS-DefaultDocument',
    'IIS-DigestAuthentication',
    'IIS-DirectoryBrowsing',
    #'IIS-FTPExtensibility',
    #'IIS-FTPServer',
    #'IIS-FTPSvc',
    'IIS-HealthAndDiagnostics',
    'IIS-HostableWebCore',
    'IIS-HttpCompressionDynamic',
    'IIS-HttpCompressionStatic',
    'IIS-HttpErrors',
    'IIS-HttpLogging',
    'IIS-HttpRedirect',
    'IIS-HttpTracing',
    #'IIS-IIS6ManagementCompatibility',
    #'IIS-IISCertificateMappingAuthentication',
    'IIS-IPSecurity',
    'IIS-ISAPIExtensions',
    'IIS-ISAPIFilter',
    #'IIS-LegacyScripts',
    #'IIS-LegacySnapIn',
    'IIS-LoggingLibraries',
    'IIS-ManagementConsole',
    'IIS-ManagementScriptingTools',
    'IIS-ManagementService',
    'IIS-Metabase',
    #'IIS-NetFxExtensibility',
    'IIS-NetFxExtensibility45',
    'IIS-ODBCLogging',
    'IIS-Performance',
    'IIS-RequestFiltering',
    'IIS-RequestMonitor',
    'IIS-Security',
    'IIS-ServerSideIncludes',
    'IIS-StaticContent',
    'IIS-URLAuthorization',
    #'IIS-WebDAV',
    'IIS-WebServer',
    'IIS-WebServerManagementTools',
    'IIS-WebServerRole',
    'IIS-WebSockets',
    'IIS-WindowsAuthentication'
    #'IIS-WMICompatibility'
)
