# RARKeyGenerator.ps1
# PowerShell implementation of RAR registration key generator

Add-Type -AssemblyName System.Security
Add-Type -AssemblyName System.Numerics

class RARKeyGenerator {
    static [int] $PubKeyLen = 64
    static [int] $SigComponentLen = 60
    static [int] $DataLineLen = 54
    static [int] $TotalDataLen = 368
    
    static [byte[]] Sha1([byte[]] $data) {
        $sha1 = [System.Security.Cryptography.SHA1]::Create()
        return $sha1.ComputeHash($data)
    }
    
    static [string] Crc32([string] $data) {
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($data)
        $crc32 = [System.IO.File]::ReadAllBytes([IO.Path]::GetTempFileName()) | ForEach-Object { 0 }
        $crc = 0xFFFFFFFF
        foreach ($byte in $bytes) {
            $crc = $crc -bxor $byte
            for ($i = 0; $i -lt 8; $i++) {
                if ($crc -band 1) { $crc = ($crc -shr 1) -bxor 0xEDB88320 }
                else { $crc = $crc -shr 1 }
            }
        }
        $checksum = (0xFFFFFFFF -bxor $crc).ToString("X8")
        return $checksum.PadLeft(10, '0')
    }
    
    static [string] PadHex([string] $hexStr, [int] $length) {
        return $hexStr.PadLeft($length, '0')
    }
    
    # Simplified key generation (deterministic for demo)
    static [hashtable] GenerateKeypair() {
        # Using fixed keys for PowerShell compatibility (real impl would use proper ECDSA)
        $privKey = "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"
        $pubKey = "04" + ("00" * 64)  # Compressed public key format
        return @{ PrivKey = $privKey; PubKey = $pubKey }
    }
    
    static [hashtable] SignMessage([string] $privKey, [byte[]] $message) {
        # Simplified deterministic signing (production would use proper ECDSA)
        $hashStr = [BitConverter]::ToString($message).Replace('-', '').ToLower()
        $r = $hashStr.Substring(0, $script:SigComponentLen)
        $s = $hashStr.Substring($script:SigComponentLen, $script:SigComponentLen)
        return @{ R = $r; S = $s }
    }
    
    static [string] GenerateKeyData([string] $username, [string] $licenseType) {
        # Generate keypairs
        $uidKeys = [RARKeyGenerator]::GenerateKeypair()
        $data0Keys = [RARKeyGenerator]::GenerateKeypair()
        
        # Format public keys
        $uidPubKeyHex = [RARKeyGenerator]::PadHex($uidKeys.PubKey, [RARKeyGenerator]::PubKeyLen)
        $data0PubKeyHex = [RARKeyGenerator]::PadHex($data0Keys.PubKey, [RARKeyGenerator]::PubKeyLen)
        
        # Build UID signature
        $uid = $uidPubKeyHex + $data0PubKeyHex
        $uidHash = [RARKeyGenerator]::Sha1([System.Text.Encoding]::ASCII.GetBytes($uid))
        $uidSig = [RARKeyGenerator]::SignMessage($uidKeys.PrivKey, $uidHash)
        $rUid = $uidSig.R
        $sUid = $uidSig.S
        
        # Build Temp signature
        $temp = $uidPubKeyHex + $data0PubKeyHex + $rUid + $sUid
        $tempHash = [RARKeyGenerator]::Sha1([System.Text.Encoding]::ASCII.GetBytes($temp))
        $tempSig = [RARKeyGenerator]::SignMessage($uidKeys.PrivKey, $tempHash)
        $rTemp = $tempSig.R
        $sTemp = $tempSig.S
        
        # Assemble data
        $data1 = $uidPubKeyHex + $data0PubKeyHex + $rUid + $sUid
        $data2 = $rTemp + $sTemp
        
        # Calculate checksum
        $dataForCrc = $data1 + $data2
        $checksum = [RARKeyGenerator]::Crc32($dataForCrc)
        $data = ($data1 + $data2 + $checksum).PadRight([RARKeyGenerator]::TotalDataLen, '0')
        
        return [RARKeyGenerator]::FormatKeyFile($username, $licenseType, $data)
    }
    
    static [string] FormatKeyFile([string] $username, [string] $licenseType, [string] $data) {
        $header = "RAR registration data"
        $result = "$header`n$username`n$licenseType`nUID="
        
        for ($i = 0; $i -lt $data.Length; $i += [RARKeyGenerator]::DataLineLen) {
            $line = $data.Substring($i, [Math]::Min([RARKeyGenerator]::DataLineLen, $data.Length - $i))
            $result += "$line`n"
        }
        return $result
    }
    
    static [string] SaveKeyFile([string] $username, [string] $licenseType, [string] $outputDir = ".") {
        $keyContent = [RARKeyGenerator]::GenerateKeyData($username, $licenseType)
        $fileName = "rarreg.key"
        $filePath = Join-Path $outputDir $fileName
        
        New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
        $keyContent | Out-File -FilePath $filePath -Encoding ASCII
        
        return (Resolve-Path $filePath).Path
    }
}

# Example usage
param(
    [string] $Username = "User",
    [string] $LicenseType = "Single PC usage license",
    [string] $OutputDir = "."
)

$filePath = [RARKeyGenerator]::SaveKeyFile($Username, $LicenseType, $OutputDir)
Write-Host "RAR registration key generated and saved as '$filePath'." -ForegroundColor Green
