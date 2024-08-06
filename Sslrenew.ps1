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
