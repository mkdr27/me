param (
    [string]$csvFilePath = "C:\path\to\your\certificates.csv"
)

# Load the CSV file
$certificates = Import-Csv -Path $csvFilePath

# Function to check compliance for a given certificate
function Check-CertificateCompliance {
    param (
        [string]$certFilePath,
        [string]$certFormat
    )

    # Load the certificate based on its format
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    if ($certFormat -eq "cer") {
        $cert.Import($certFilePath)
    } elseif ($certFormat -eq "pfx") {
        $cert.Import($certFilePath, $null, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
    } else {
        Write-Host "Unsupported certificate format: $certFormat"
        return
    }

    # Compliance criteria
    $complianceStatus = $true
    $failedConditions = @()

    # Define the number of days for certificate validity check
    $validityDays = 397

    # Calculate the certificate validity period
    $validFrom = $cert.NotBefore
    $validTo = $cert.NotAfter
    $validityPeriod = ($validTo - $validFrom).Days

    # Check if the certificate's validity period is less than 397 days
    if ($validityPeriod -ge $validityDays) {
        $complianceStatus = $false
        $failedConditions += "Validity period is greater than or equal to 397 days."
    }

    # Get key algorithm and key size
    $keyAlgorithm = $cert.PublicKey.Oid.FriendlyName
    $keySize = $cert.PublicKey.Key.KeySize

    # Check key algorithm and key size
    if ($keyAlgorithm -eq "RSA" -and $keySize -le 2048) {
        $complianceStatus = $false
        $failedConditions += "RSA key size is less than or equal to 2048 bits."
    } elseif ($keyAlgorithm -eq "ECC" -and $keySize -le 256) {
        $complianceStatus = $false
        $failedConditions += "ECC key size is less than or equal to 256 bits."
    } elseif ($keyAlgorithm -notin @("RSA", "ECC")) {
        $complianceStatus = $false
        $failedConditions += "Unsupported key algorithm: $keyAlgorithm."
    }

    # Get signature algorithm
    $signatureAlgorithm = $cert.SignatureAlgorithm.FriendlyName

    # Check if the signature algorithm is one of the allowed algorithms
    $allowedSignatureAlgorithms = @("sha256ECDSA", "sha256RSA", "sha512RSA", "sha384RSA")
    if ($signatureAlgorithm -notin $allowedSignatureAlgorithms) {
        $complianceStatus = $false
        $failedConditions += "Unsupported signature algorithm: $signatureAlgorithm."
    }

    # Check if the certificate's subject name contains a wildcard
    $subjectName = $cert.Subject
    $wildcardInSubject = $subjectName -like "*`**"
    if ($wildcardInSubject) {
        $complianceStatus = $false
        $failedConditions += "Wildcard found in subject name."
    }

    # Get Subject Alternative Names (SANs)
    $sanNames = @()
    $wildcardInSANs = $false
    foreach ($extension in $cert.Extensions) {
        if ($extension.Oid.FriendlyName -eq "Subject Alternative Name") {
            $sanString = $extension.Format($false)
            $sanNames = $sanString -split "\s*,\s*"
            
            # Check if any SAN contains a wildcard
            foreach ($san in $sanNames) {
                if ($san -like "*`**") {
                    $wildcardInSANs = $true
                    break
                }
            }
            if ($wildcardInSANs) {
                $complianceStatus = $false
                $failedConditions += "Wildcard found in Subject Alternative Name."
            }
        }
    }

    # Check if the issuer is one of the allowed issuers
    $allowedIssuers = @("CN=DigiCert Global Root CA", "CN=DigiCert Global Root G2")
    $issuer = $cert.Issuer
    if ($issuer -notin $allowedIssuers) {
        $complianceStatus = $false
        $failedConditions += "Issuer is not in the allowed list."
    }

    # Return certificate details, compliance status, and failed conditions
    return [PSCustomObject]@{
        Thumbprint = $cert.Thumbprint
        Subject = $cert.Subject
        ValidFrom = $validFrom
        ValidTo = $validTo
        ValidityPeriod = "$validityPeriod days"
        KeyAlgorithm = $keyAlgorithm
        KeySize = $keySize
        SignatureAlgorithm = $signatureAlgorithm
        Issuer = $issuer
        AlternateDNSNames = $sanNames
        WildcardInSubject = $wildcardInSubject
        WildcardInSANs = $wildcardInSANs
        ComplianceStatus = if ($complianceStatus) { "Compliant" } else { "Non-Compliant" }
        FailedConditions = $failedConditions -join "; "
    }
}

# Loop through each certificate in the CSV and check compliance
$results = @()
foreach ($cert in $certificates) {
    $result = Check-CertificateCompliance -certFilePath $cert.CertificateLocation -certFormat $cert.Format
    $results += [PSCustomObject]@{
        CertificateName = $cert.CertificateName
        CertificateDetails = $result
    }
}

# Output all results
$results | Format-Table -AutoSize

-----
param (
    [string]$cerFilePath = "C:\path\to\your\certificate.cer"
)

# Load the certificate from the .cer file
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
$cert.Import($cerFilePath)

# Compliance criteria
$complianceStatus = $true

# Define the number of days for certificate validity check
$validityDays = 397

# Calculate the certificate validity period
$validFrom = $cert.NotBefore
$validTo = $cert.NotAfter
$validityPeriod = ($validTo - $validFrom).Days

# Check if the certificate's validity period is less than 397 days
if ($validityPeriod -ge $validityDays) {
    $complianceStatus = $false
}

# Get key algorithm and key size
$keyAlgorithm = $cert.PublicKey.Oid.FriendlyName
$keySize = $cert.PublicKey.Key.KeySize

# Check key algorithm and key size
if (($keyAlgorithm -eq "RSA" -and $keySize -le 2048) -or ($keyAlgorithm -eq "ECC" -and $keySize -le 256) -or ($keyAlgorithm -notin @("RSA", "ECC"))) {
    $complianceStatus = $false
}

# Get signature algorithm
$signatureAlgorithm = $cert.SignatureAlgorithm.FriendlyName

# Check if the signature algorithm is one of the allowed algorithms
$allowedSignatureAlgorithms = @("sha256ECDSA", "sha256RSA", "sha512RSA", "sha384RSA")
if ($signatureAlgorithm -notin $allowedSignatureAlgorithms) {
    $complianceStatus = $false
}

# Check if the certificate's subject name contains a wildcard
$subjectName = $cert.Subject
$wildcardInSubject = $subjectName -like "*`**"
if ($wildcardInSubject) {
    $complianceStatus = $false
}

# Get Subject Alternative Names (SANs)
$sanNames = @()
$wildcardInSANs = $false
foreach ($extension in $cert.Extensions) {
    if ($extension.Oid.FriendlyName -eq "Subject Alternative Name") {
        $sanString = $extension.Format($false)
        $sanNames = $sanString -split "\s*,\s*"
        
        # Check if any SAN contains a wildcard
        foreach ($san in $sanNames) {
            if ($san -like "*`**") {
                $wildcardInSANs = $true
                break
            }
        }
        if ($wildcardInSANs) {
            $complianceStatus = $false
            break
        }
    }
}

# Check if the issuer is one of the allowed issuers
$allowedIssuers = @("CN=DigiCert Global Root CA", "CN=DigiCert Global Root G2")
$issuer = $cert.Issuer
if ($issuer -notin $allowedIssuers) {
    $complianceStatus = $false
}

# Output certificate details and compliance status
[PSCustomObject]@{
    Thumbprint = $cert.Thumbprint
    Subject = $cert.Subject
    ValidFrom = $validFrom
    ValidTo = $validTo
    ValidityPeriod = "$validityPeriod days"
    KeyAlgorithm = $keyAlgorithm
    KeySize = $keySize
    SignatureAlgorithm = $signatureAlgorithm
    Issuer = $issuer
    AlternateDNSNames = $sanNames
    WildcardInSubject = $wildcardInSubject
    WildcardInSANs = $wildcardInSANs
    ComplianceStatus = if ($complianceStatus) { "Compliant" } else { "Non-Compliant" }
}


param (
    [string]$cerFilePath = "C:\path\to\your\certificate.cer"
)

# Load the certificate from the .cer file
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
$cert.Import($cerFilePath)

# Define the number of days for certificate validity check
$validityDays = 397

# Calculate the certificate validity period
$validFrom = $cert.NotBefore
$validTo = $cert.NotAfter
$validityPeriod = ($validTo - $validFrom).Days

# Check if the certificate's subject name contains a wildcard
$subjectName = $cert.Subject
$wildcardInSubject = $subjectName -like "*CN=*.*"

# Get Subject Alternative Names (SANs)
$sanNames = @()
$wildcardInSANs = $false
foreach ($extension in $cert.Extensions) {
    if ($extension.Oid.FriendlyName -eq "Subject Alternative Name") {
        $sanString = $extension.Format($false)
        $sanNames = $sanString -split "\s*,\s*"
        
        # Check if any SAN contains a wildcard
        foreach ($san in $sanNames) {
            if ($san -like "DNS Name=*.*") {
                $wildcardInSANs = $true
                break
            }
        }
        break
    }
}

if ($validityPeriod -lt $validityDays) {
    # Get key algorithm and key size
    $keyAlgorithm = $cert.PublicKey.Oid.FriendlyName
    $keySize = $cert.PublicKey.Key.KeySize
    
    # Get signature algorithm
    $signatureAlgorithm = $cert.SignatureAlgorithm.FriendlyName
    
    # Get issuer details
    $issuer = $cert.Issuer

    # Output certificate details
    [PSCustomObject]@{
        Thumbprint = $cert.Thumbprint
        Subject = $cert.Subject
        ValidFrom = $validFrom
        ValidTo = $validTo
        ValidityPeriod = "$validityPeriod days"
        KeyAlgorithm = $keyAlgorithm
        KeySize = $keySize
        SignatureAlgorithm = $signatureAlgorithm
        Issuer = $issuer
        AlternateDNSNames = $sanNames
        WildcardInSubject = $wildcardInSubject
        WildcardInSANs = $wildcardInSANs
    }
} else {
    Write-Host "The certificate validity period is more than $validityDays days."
}


param (
    [string]$cerFilePath = "C:\path\to\your\certificate.cer"
)

# Load the certificate from the .cer file
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
$cert.Import($cerFilePath)

# Define the number of days for certificate validity check
$validityDays = 397

# Calculate the certificate validity period
$validFrom = $cert.NotBefore
$validTo = $cert.NotAfter
$validityPeriod = ($validTo - $validFrom).Days

# Check if the certificate's name contains a wildcard
$subjectName = $cert.Subject
$wildcardExists = $subjectName -like "*CN=*.example.com*"

# Get Subject Alternative Names (SANs)
$sanNames = @()
foreach ($extension in $cert.Extensions) {
    if ($extension.Oid.FriendlyName -eq "Subject Alternative Name") {
        $sanString = $extension.Format($false)
        $sanNames = $sanString -split "\s*,\s*"
        break
    }
}

if ($validityPeriod -lt $validityDays) {
    # Get key algorithm and key size
    $keyAlgorithm = $cert.PublicKey.Oid.FriendlyName
    $keySize = $cert.PublicKey.Key.KeySize
    
    # Get signature algorithm
    $signatureAlgorithm = $cert.SignatureAlgorithm.FriendlyName
    
    # Get issuer details
    $issuer = $cert.Issuer

    # Output certificate details
    [PSCustomObject]@{
        Thumbprint = $cert.Thumbprint
        Subject = $cert.Subject
        ValidFrom = $validFrom
        ValidTo = $validTo
        ValidityPeriod = "$validityPeriod days"
        KeyAlgorithm = $keyAlgorithm
        KeySize = $keySize
        SignatureAlgorithm = $signatureAlgorithm
        Issuer = $issuer
        AlternateDNSNames = $sanNames
        WildcardExists = $wildcardExists
    }
} else {
    Write-Host "The certificate validity period is more than $validityDays days."
}


param (
    [string]$cerFilePath = "C:\path\to\your\certificate.cer"
)

# Load the certificate from the .cer file
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
$cert.Import($cerFilePath)

# Define the number of days for certificate validity check
$validityDays = 397

# Calculate the certificate validity period
$validFrom = $cert.NotBefore
$validTo = $cert.NotAfter
$validityPeriod = ($validTo - $validFrom).Days

if ($validityPeriod -lt $validityDays) {
    # Get key algorithm and key size
    $keyAlgorithm = $cert.PublicKey.Oid.FriendlyName
    $keySize = $cert.PublicKey.Key.KeySize
    
    # Get signature algorithm
    $signatureAlgorithm = $cert.SignatureAlgorithm.FriendlyName
    
    # Get issuer details
    $issuer = $cert.Issuer

    # Output certificate details
    [PSCustomObject]@{
        Thumbprint = $cert.Thumbprint
        Subject = $cert.Subject
        ValidFrom = $validFrom
        ValidTo = $validTo
        ValidityPeriod = "$validityPeriod days"
        KeyAlgorithm = $keyAlgorithm
        KeySize = $keySize
        SignatureAlgorithm = $signatureAlgorithm
        Issuer = $issuer
    }
} else {
    Write-Host "The certificate validity period is more than $validityDays days."
}


param (
    [string]$endpoint = "your-endpoint.com",
    [int]$port = 443
)

function Get-CertificateFromEndpoint {
    param (
        [string]$hostname,
        [int]$port
    )

    try {
        $client = New-Object System.Net.Sockets.TcpClient($hostname, $port)
        $sslStream = New-Object System.Net.Security.SslStream($client.GetStream(), $false, {$true})
        $sslStream.AuthenticateAsClient($hostname)
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($sslStream.RemoteCertificate)
        $client.Close()
        return $cert
    } catch {
        Write-Error "Failed to retrieve the certificate from $hostname:$port"
        return $null
    }
}

# Define the number of days for certificate validity check
$validityDays = 397

# Retrieve the certificate from the endpoint
$certificate = Get-CertificateFromEndpoint -hostname $endpoint -port $port

if ($certificate) {
    # Calculate the certificate validity period
    $validFrom = $certificate.NotBefore
    $validTo = $certificate.NotAfter
    $validityPeriod = ($validTo - $validFrom).Days

    if ($validityPeriod -lt $validityDays) {
        # Get key algorithm and key size
        $keyAlgorithm = $certificate.PublicKey.Oid.FriendlyName
        $keySize = $certificate.PublicKey.Key.KeySize
        
        # Get signature algorithm
        $signatureAlgorithm = $certificate.SignatureAlgorithm.FriendlyName
        
        # Get issuer details
        $issuer = $certificate.Issuer

        # Output certificate details
        [PSCustomObject]@{
            Thumbprint = $certificate.Thumbprint
            Subject = $certificate.Subject
            ValidFrom = $validFrom
            ValidTo = $validTo
            ValidityPeriod = "$validityPeriod days"
            KeyAlgorithm = $keyAlgorithm
            KeySize = $keySize
            SignatureAlgorithm = $signatureAlgorithm
            Issuer = $issuer
        }
    } else {
        Write-Host "The certificate validity period is more than $validityDays days."
    }
}


param (
    [string]$endpoint = "https://your-endpoint.com"
)

function Get-CertificateFromEndpoint {
    param (
        [string]$url
    )

    try {
        $request = [Net.HttpWebRequest]::Create($url)
        $request.ServerCertificateValidationCallback = {$true}
        $request.GetResponse() | Out-Null
        $cert = $request.ServicePoint.Certificate
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $cert
        return $cert
    } catch {
        Write-Error "Failed to retrieve the certificate from $url"
        return $null
    }
}

# Define the number of days for certificate validity check
$validityDays = 397

# Retrieve the certificate from the endpoint
$certificate = Get-CertificateFromEndpoint -url $endpoint

if ($certificate) {
    # Calculate the certificate validity period
    $validFrom = $certificate.NotBefore
    $validTo = $certificate.NotAfter
    $validityPeriod = ($validTo - $validFrom).Days

    if ($validityPeriod -lt $validityDays) {
        # Get key algorithm and key size
        $keyAlgorithm = $certificate.PublicKey.Oid.FriendlyName
        $keySize = $certificate.PublicKey.Key.KeySize
        
        # Get signature algorithm
        $signatureAlgorithm = $certificate.SignatureAlgorithm.FriendlyName
        
        # Get issuer details
        $issuer = $certificate.Issuer

        # Output certificate details
        [PSCustomObject]@{
            Thumbprint = $certificate.Thumbprint
            Subject = $certificate.Subject
            ValidFrom = $validFrom
            ValidTo = $validTo
            ValidityPeriod = "$validityPeriod days"
            KeyAlgorithm = $keyAlgorithm
            KeySize = $keySize
            SignatureAlgorithm = $signatureAlgorithm
            Issuer = $issuer
        }
    } else {
        Write-Host "The certificate validity period is more than $validityDays days."
    }
}


# Path to the PFX file
$pfxPath = "C:\path\to\your\certificate.pfx"

# Prompt for the PFX file password
$pfxPassword = Read-Host -AsSecureString -Prompt "Enter the password for the PFX file"

# Import the PFX file
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
$cert.Import($pfxPath, $pfxPassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)

# Define the number of days for certificate validity check
$validityDays = 397

# Calculate the certificate validity period
$validFrom = $cert.NotBefore
$validTo = $cert.NotAfter
$validityPeriod = ($validTo - $validFrom).Days

if ($validityPeriod -lt $validityDays) {
    # Get key algorithm and key size
    $keyAlgorithm = $cert.PublicKey.Oid.FriendlyName
    $keySize = $cert.PublicKey.Key.KeySize
    
    # Get signature algorithm
    $signatureAlgorithm = $cert.SignatureAlgorithm.FriendlyName
    
    # Get issuer details
    $issuer = $cert.Issuer

    # Output certificate details
    [PSCustomObject]@{
        Thumbprint = $cert.Thumbprint
        Subject = $cert.Subject
        ValidFrom = $validFrom
        ValidTo = $validTo
        ValidityPeriod = "$validityPeriod days"
        KeyAlgorithm = $keyAlgorithm
        KeySize = $keySize
        SignatureAlgorithm = $signatureAlgorithm
        Issuer = $issuer
    }
} else {
    Write-Host "The certificate validity period is more than $validityDays days."
}


# Function to update site binding with a new SSL certificate
function Update-SiteBindingWithCertificate {
    param (
        [string]$siteName,
        [int]$port,
        [string]$certThumbprint
    )

    $site = Get-WebSite -Name $siteName
    $binding = $site.Bindings | Where-Object { $_.Port -eq $port -and $_.Protocol -eq "https" }
    
    $binding.RemoveSslCertificate()
    $binding.AddSslCertificate($certThumbprint, "My")
    
    $site | Set-WebSite -Force
    Write-Host "SSL certificate updated for $siteName on port $port"
}

# Function to import a new SSL certificate and get its thumbprint
function Import-CertificateAndGetThumbprint {
    param (
        [string]$certificatePath,
        [string]$certificatePassword
    )

    $cert = Import-PfxCertificate -FilePath $certificatePath -CertStoreLocation Cert:\LocalMachine\My -Password (ConvertTo-SecureString -String $certificatePassword -AsPlainText -Force)
    $thumbprint = $cert.Thumbprint

    Write-Host "Thumbprint of the imported certificate: $thumbprint"
}

# Function to verify a site's SSL certificate
function Verify-SiteSSL {
    param (
        [string]$siteUrl,
        [string]$expectedThumbprint
    )

    # Check if the SSL certificate is updated
    try {
        $response = Invoke-WebRequest -Uri $siteUrl -UseBasicParsing
        $thumbprint = $response.Headers['X-SSL-Cert']
        
        if ($thumbprint -eq $expectedThumbprint) {
            Write-Host "The SSL certificate for $siteUrl is updated with the latest certificate."
        } else {
            Write-Host "The SSL certificate for $siteUrl does not match the expected thumbprint. Current thumbprint: $thumbprint"
        }
    } catch {
        Write-Host "Error connecting to $siteUrl. $_"
    }
}

# Function to backup an existing SSL certificate
function Backup-Certificate {
    param (
        [string]$thumbprint,
        [string]$backupPath
    )

    # Export the certificate without a password
    Export-PfxCertificate -Cert Cert:\LocalMachine\My\$thumbprint -FilePath $backupPath -NoExportPrivateKey

    Write-Host "Backup of the certificate with thumbprint $thumbprint (without password) is created at $backupPath"
}

# Example Usage:
# Update-SiteBindingWithCertificate -siteName "YourSiteName" -port 443 -certThumbprint "YourNewCertThumbprint"
# Import-CertificateAndGetThumbprint -certificatePath "C:\Path\To\Your\Certificate.pfx" -certificatePassword "YourCertificatePassword"
# Verify-SiteSSL -siteUrl "https://yourwebsite.com" -expectedThumbprint "YourExpectedThumbprint"
# Backup-Certificate -thumbprint "YourExistingThumbprint" -backupPath "C:\Path\To\Backup\CertificateBackup.pfx"
