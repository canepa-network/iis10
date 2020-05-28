# iis config script

$DefaultFeatures = @(
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

function setup-ssl (){
 # Visit (https://www.hass.de/content/setup-microsoft-windows-or-iis-ssl-perfect-forward-secrecy-and-tls-12) For Info:

        # Disable Multi-Protocol Unified Hello
        New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' -Force | Out-Null
        New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
        New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client' -Force | Out-Null
        New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
        Write-Host 'Multi-Protocol Unified Hello has been disabled.'

        # Disable PCT 1.0
        New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' -Force | Out-Null
        New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
        New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client' -Force | Out-Null
        New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
        Write-Host 'PCT 1.0 has been disabled.'

        # Disable SSL 2.0 (PCI Compliance)
        New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Force | Out-Null
        New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
        New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -Force | Out-Null
        New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
        Write-Host 'SSL 2.0 has been disabled.'

        # NOTE: If you disable SSL 3.0 the you may lock out some people still using
        # Windows XP with IE6/7. Without SSL 3.0 enabled, there is no protocol available
        # for these people to fall back. Safer shopping certifications may require that
        # you disable SSLv3.
        #
        # Disable SSL 3.0 (PCI Compliance) and enable "Poodle" protection
        New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Force | Out-Null
        New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
        New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Force | Out-Null
        New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
        Write-Host 'SSL 3.0 has been disabled.'

        # Disable TLS 1.0 for client and server SCHANNEL communications
        New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Force | Out-Null
        New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
        New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Force | Out-Null
        New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
        Write-Host 'TLS 1.0 has been disabled.'

        # Add and Disable TLS 1.1 for client and server SCHANNEL communications
        New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Force | Out-Null
        New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
        New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Force | Out-Null
        New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
        Write-Host 'TLS 1.1 has been disabled.'

        # Add and Enable TLS 1.2 for client and server SCHANNEL communications
        New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force | Out-Null
        New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
        New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force | Out-Null
        New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
        Write-Host 'TLS 1.2 has been enabled.'

        # Re-create the ciphers key.
        New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers' -Force | Out-Null

        # Disable insecure/weak ciphers.
        $insecureCiphers = @(
            'DES 56/56',
            'NULL',
            'RC2 128/128',
            'RC2 40/128',
            'RC2 56/128',
            'RC4 40/128',
            'RC4 56/128',
            'RC4 64/128',
            'RC4 128/128',
            'Triple DES 168'
        )
        Foreach ($insecureCipher in $insecureCiphers) {
            $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey($insecureCipher)
            $key.SetValue('Enabled', 0, 'DWord')
            $key.close()
            Write-Host "Weak cipher $insecureCipher has been disabled."
        }

        # Enable new secure ciphers.
        # - RC4: It is recommended to disable RC4, but you may lock out WinXP/IE8 if you enforce this. This is a requirement for FIPS 140-2.
        # - 3DES: It is recommended to disable these in near future. This is the last cipher supported by Windows XP.
        # - Windows Vista and before 'Triple DES 168' was named 'Triple DES 168/168' per https://support.microsoft.com/en-us/kb/245030
        $secureCiphers = @(
            'AES 128/128',
            'AES 256/256'
        )
        Foreach ($secureCipher in $secureCiphers) {
            $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey($secureCipher)
            New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$secureCipher" -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
            $key.close()
            Write-Host "Strong cipher $secureCipher has been enabled."
        }

        # Set hashes configuration.
        New-Item 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes' -Force | Out-Null
        New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5' -Force | Out-Null
        New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null

        $secureHashes = @(
            'SHA',
            'SHA256',
            'SHA384',
            'SHA512'
        )
        Foreach ($secureHash in $secureHashes) {
            $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes', $true).CreateSubKey($secureHash)
            New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\$secureHash" -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
            $key.close()
            Write-Host "Hash $secureHash has been enabled."
        }

        # Set KeyExchangeAlgorithms configuration.
        New-Item 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms' -Force | Out-Null
        $secureKeyExchangeAlgorithms = @(
            'Diffie-Hellman',
            'ECDH',
            'PKCS'
        )
        Foreach ($secureKeyExchangeAlgorithm in $secureKeyExchangeAlgorithms) {
            $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms', $true).CreateSubKey($secureKeyExchangeAlgorithm)
            New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\$secureKeyExchangeAlgorithm" -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
            $key.close()
            Write-Host "KeyExchangeAlgorithm $secureKeyExchangeAlgorithm has been enabled."
        }

        # Microsoft Security Advisory 3174644 - Updated Support for Diffie-Hellman Key Exchange
        # https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2016/3174644
        Write-Host 'Configure longer DHE key shares for TLS servers.'
        New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" -name 'ServerMinKeyBitLength' -value '2048' -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" -name 'ClientMinKeyBitLength' -value '2048' -PropertyType 'DWord' -Force | Out-Null

        # https://support.microsoft.com/en-us/help/3174644/microsoft-security-advisory-updated-support-for-diffie-hellman-key-exc
        New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS" -name 'ClientMinKeyBitLength' -value '2048' -PropertyType 'DWord' -Force | Out-Null

        # Set cipher suites order as secure as possible (Enables Perfect Forward Secrecy).
        $os = Get-CimInstance -class Win32_OperatingSystem -Verbose:$false
        if ([System.Version]$os.Version -lt [System.Version]'10.0') {
            Write-Host 'Use cipher suites order for Windows 2008/2008R2/2012/2012R2.'
            $cipherSuitesOrder = @(
                'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P521',
                'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P384',
                'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P256',
                'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P521',
                'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P384',
                'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256',
                'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P521',
                'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P384',
                'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P256',
                'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P521',
                'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P384',
                'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P256',
                'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P521',
                'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384',
                'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P521',
                'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P384',
                'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P256',
                'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P521',
                'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P384',
                'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P521',
                'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P384',
                'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P256',
                'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P521',
                'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P384',
                'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P256',
                'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P521',
                'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P384',
                'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P256',
                # Below are the only AEAD ciphers available on Windows 2012R2 and earlier.
                # - RSA certificates need below ciphers, but ECDSA certificates (EV) may not.
                # - We get penalty for not using AEAD suites with RSA certificates.
                'TLS_RSA_WITH_AES_256_GCM_SHA384',
                'TLS_RSA_WITH_AES_128_GCM_SHA256',
                'TLS_RSA_WITH_AES_256_CBC_SHA256',
                'TLS_RSA_WITH_AES_128_CBC_SHA256',
                'TLS_RSA_WITH_AES_256_CBC_SHA',
                'TLS_RSA_WITH_AES_128_CBC_SHA'
            )
        }
        else {
            Write-Host 'Use cipher suites order for Windows 10/2016 and later.'
            $cipherSuitesOrder = @(
                'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
                'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
                'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
                'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
                'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
                'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
                'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
                'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
                'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
                'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
                'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
                'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA'
            )
        }
        $cipherSuitesAsString = [string]::join(',', $cipherSuitesOrder)
        # One user reported this key does not exists on Windows 2012R2. Cannot repro myself on a brand new Windows 2012R2 core machine. Adding this just to be save.
        New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -ErrorAction SilentlyContinue
        New-ItemProperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -name 'Functions' -value $cipherSuitesAsString -PropertyType 'String' -Force | Out-Null

        # Exchange Server TLS guidance Part 2: Enabling TLS 1.2 and Identifying Clients Not Using It
        # https://blogs.technet.microsoft.com/exchange/2018/04/02/exchange-server-tls-guidance-part-2-enabling-tls-1-2-and-identifying-clients-not-using-it/
        # New IIS functionality to help identify weak TLS usage
        # https://cloudblogs.microsoft.com/microsoftsecure/2017/09/07/new-iis-functionality-to-help-identify-weak-tls-usage/
        Write-Host 'Enable TLS 1.2 for .NET 3.5 and .NET 4.x'
        New-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" -name 'SystemDefaultTlsVersions' -value 1 -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" -name 'SchUseStrongCrypto' -value 1 -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -name 'SystemDefaultTlsVersions' -value 1 -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -name 'SchUseStrongCrypto' -value 1 -PropertyType 'DWord' -Force | Out-Null
        if (Test-Path 'HKLM:\SOFTWARE\Wow6432Node') {
            New-ItemProperty -path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727" -name 'SystemDefaultTlsVersions' -value 1 -PropertyType 'DWord' -Force | Out-Null
            New-ItemProperty -path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727" -name 'SchUseStrongCrypto' -value 1 -PropertyType 'DWord' -Force | Out-Null
            New-ItemProperty -path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -name 'SystemDefaultTlsVersions' -value 1 -PropertyType 'DWord' -Force | Out-Null
            New-ItemProperty -path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -name 'SchUseStrongCrypto' -value 1 -PropertyType 'DWord' -Force | Out-Null
        }

        # DefaultSecureProtocols Value	Decimal value  Protocol enabled
        # 0x00000008                                8  Enable SSL 2.0 by default
        # 0x00000020                               32  Enable SSL 3.0 by default
        # 0x00000080                              128  Enable TLS 1.0 by default
        # 0x00000200                              512  Enable TLS 1.1 by default
        # 0x00000800                             2048  Enable TLS 1.2 by default
        $defaultSecureProtocols = @(
            '2048'  # TLS 1.2
        )
        $defaultSecureProtocolsSum = ($defaultSecureProtocols | Measure-Object -Sum).Sum

        # Update to enable TLS 1.2 as a default secure protocols in WinHTTP in Windows
        # https://support.microsoft.com/en-us/help/3140245/update-to-enable-tls-1-1-and-tls-1-2-as-a-default-secure-protocols-in

        # Verify if hotfix KB3140245 is installed.
        $file_version_winhttp_dll = (Get-Item $env:windir\System32\winhttp.dll).VersionInfo | ForEach-Object { ("{0}.{1}.{2}.{3}" -f $_.ProductMajorPart, $_.ProductMinorPart, $_.ProductBuildPart, $_.ProductPrivatePart) }
        $file_version_webio_dll = (Get-Item $env:windir\System32\Webio.dll).VersionInfo | ForEach-Object { ("{0}.{1}.{2}.{3}" -f $_.ProductMajorPart, $_.ProductMinorPart, $_.ProductBuildPart, $_.ProductPrivatePart) }
        if ([System.Version]$file_version_winhttp_dll -lt [System.Version]"6.1.7601.23375" -or [System.Version]$file_version_webio_dll -lt [System.Version]"6.1.7601.23375") {
            Write-Host 'WinHTTP: Cannot enable TLS 1.2. Please see https://support.microsoft.com/en-us/help/3140245/update-to-enable-tls-1-1-and-tls-1-2-as-a-default-secure-protocols-in for system requirements.'
        }
        else {
            Write-Host 'WinHTTP: Minimum system requirements are met.'
            Write-Host 'WinHTTP: Activate TLS 1.2 only.'
            New-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -name 'DefaultSecureProtocols' -value $defaultSecureProtocolsSum -PropertyType 'DWord' -Force | Out-Null
            if (Test-Path 'HKLM:\SOFTWARE\Wow6432Node') {
                # WinHttp key seems missing in Windows 2019 for unknown reasons.
                New-Item 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -ErrorAction SilentlyContinue | Out-Null
                New-ItemProperty -path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -name 'DefaultSecureProtocols' -value $defaultSecureProtocolsSum -PropertyType 'DWord' -Force | Out-Null
            }
        }

        Write-Host 'Windows Internet Explorer: Activate TLS 1.2 only.'
        New-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -name 'SecureProtocols' -value $defaultSecureProtocolsSum -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' -name 'SecureProtocols' -value $defaultSecureProtocolsSum -PropertyType 'DWord' -Force | Out-Null

}

function move-iis (){
param(
$drive = 'D'
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

function setup-drive (){
param(
$drive = 'D',
[int]$size = 10
)
        # Make Room for new Partition
        $Par = Get-Partition | Where-Object { $_.DriveLetter -eq "$((Get-Location).Drive.Name)" } | Select-Object -Property *
        $Disk = $($Par.DiskNumber)
        $ID = $($Par.PartitionNumber)
        $New = [math]::round(($Par.Size - ([int64][scriptblock]::Create("$size" + 'Gb').Invoke()[0])))
        $null = Resize-Partition -DiskNumber "$Disk" -PartitionNumber $ID -Size $New | Out-Null

        # Format New Partition
        $null = New-Partition -DiskNumber $Disk -UseMaximumSize -AssignDriveLetter:$False | Format-Volume -FileSystem 'NTFS' -NewFileSystemLabel 'iis' -confirm:$False
        $NewPar = Get-Partition | Where-Object { ($_.IsBoot -ne $True) -and ($_.IsSystem -ne $True) -and (-not $_.DriveLetter) } | Select-Object *
        $null = Set-Partition -DiskNumber $($NewPar.DiskNumber) -PartitionNumber $NewPar.PartitionNumber -NewDriveLetter "$drive"
        Do {
            $test = $False
            if (Test-Path "${drive}:\") {
                $test = $true
            }
            $null = Get-PSDrive
            Start-Sleep -Seconds 1
        }until($test -eq $true)
}


