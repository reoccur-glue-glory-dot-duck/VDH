if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $arg = if ($PSCommandPath) { "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Channel $Channel" }
           else { "-NoProfile -ExecutionPolicy Bypass -Command `"&{`$env:EDGE_CHANNEL='$Channel'; irm https://go.bibica.net/vdh | iex}`"" }
    Start-Process powershell.exe $arg -Verb RunAs
    exit
}

# ── CONFIG ────────────────────────────────────────────────────────────────
$CRX_URL    = 'https://edge.microsoft.com/extensionwebstorebase/v1/crx?response=redirect&prod=edgecrx&os=win&arch=x64&osArch=x64&nacl_arch=x86-64&prodchannel=unknown&prodversion=120.0.0.0&acceptformat=crx3&x=id%3Djmkaglaafmhbcpleggkmaliipiilhldn%26installsource%3Dondemand%26uc'
$OUTPUT_DIR = 'C:\video_download_helper'
$CRX_TEMP   = "$env:TEMP\vdh_original.crx"
$ZIP_TEMP   = "$env:TEMP\vdh_original.zip"

# ── STEP 1: Download CRX ─────────────────────────────────────────────────
Write-Host "[1/5] Downloading VDH CRX from Edge store..."
$wc = New-Object System.Net.WebClient
$wc.DownloadFile($CRX_URL, $CRX_TEMP)
$crxSize = [Math]::Round((Get-Item $CRX_TEMP).Length / 1KB)
Write-Host "      Downloaded: $CRX_TEMP ($crxSize KB)"

# ── STEP 2: Extract CRX ──────────────────────────────────────────────────
# CRX3 format: magic(4) + version(4) + header_size(4) + protobuf(header_size) + ZIP
Write-Host "[2/5] Extracting CRX..."
$crxBytes = [IO.File]::ReadAllBytes($CRX_TEMP)
$magic    = [Text.Encoding]::ASCII.GetString($crxBytes[0..3])
if ($magic -ne 'Cr24') {
    Write-Error "Invalid CRX file (expected magic 'Cr24', got '$magic')"
    exit 1
}
$headerSize = [BitConverter]::ToInt32($crxBytes, 8)
$zipStart   = 12 + $headerSize
$zipBytes   = $crxBytes[$zipStart..($crxBytes.Length - 1)]
[IO.File]::WriteAllBytes($ZIP_TEMP, $zipBytes)

if (Test-Path $OUTPUT_DIR) { Remove-Item $OUTPUT_DIR -Recurse -Force }
Expand-Archive -Path $ZIP_TEMP -DestinationPath $OUTPUT_DIR -Force

# Remove _metadata (Chrome internal, not needed for Load unpacked)
$metaDir = Join-Path $OUTPUT_DIR '_metadata'
if (Test-Path $metaDir) { Remove-Item $metaDir -Recurse -Force }

$extVersion = (Get-Content (Join-Path $OUTPUT_DIR 'manifest.json') | ConvertFrom-Json).version
Write-Host "      Extracted v$extVersion to: $OUTPUT_DIR"

# ── STEP 3: Generate ES256 Key Pair and Sign LIFETIME JWT ─────────────────
Write-Host "[3/5] Generating ES256 key pair and signing LIFETIME JWT..."

function Base64UrlEncode($bytes) {
    return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

# Generate P-256 ECDSA key pair using Windows CNG
$ecdsa = [Security.Cryptography.ECDsaCng]::new(256)
$ecdsa.HashAlgorithm = [Security.Cryptography.CngAlgorithm]::Sha256

# Build SPKI DER from raw CNG public key blob
# CNG EccPublicBlob: magic(4) + keySize(4) + X(32) + Y(32)
$pubBlob = $ecdsa.Key.Export([Security.Cryptography.CngKeyBlobFormat]::EccPublicBlob)
$X       = $pubBlob[8..39]
$Y       = $pubBlob[40..71]
$point   = [byte[]]@(0x04) + $X + $Y

# SPKI DER wrapper for P-256 EC public key (RFC 5480)
$algId   = [byte[]](0x30,0x13,0x06,0x07,0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01,
                    0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07)
$bitStr  = [byte[]](0x03,0x42,0x00) + $point
$spki    = [byte[]](0x30,0x59) + $algId + $bitStr

# Encode to PEM with \n line endings (not \r\n - browser requires \n)
$b64Body  = [Convert]::ToBase64String($spki)
$pemLines = for ($i = 0; $i -lt $b64Body.Length; $i += 64) {
    $b64Body.Substring($i, [Math]::Min(64, $b64Body.Length - $i))
}
$pubKeyPem = "-----BEGIN PUBLIC KEY-----`n" + ($pemLines -join "`n") + "`n-----END PUBLIC KEY-----`n"

# Sign JWT with IEEE P1363 format (raw R||S = 64 bytes) as required by ES256
$headerJson  = '{"alg":"ES256","typ":"JWT"}'
$payloadJson = '{"iat":0,"user_id":1,"store":"google","jti":"patched-lifetime-jti","valid_until":9999999999,"exp":9999999999,"developer":false,"entitlement_type":"LIFETIME"}'
$headerB64   = Base64UrlEncode([Text.Encoding]::UTF8.GetBytes($headerJson))
$payloadB64  = Base64UrlEncode([Text.Encoding]::UTF8.GetBytes($payloadJson))
$sigBytes    = $ecdsa.SignData([Text.Encoding]::UTF8.GetBytes("$headerB64.$payloadB64"))
$jwt         = "$headerB64.$payloadB64.$(Base64UrlEncode $sigBytes)"

Write-Host "      Signature: $($sigBytes.Length) bytes (expected 64)"

# ── STEP 4: Patch service/main.js ────────────────────────────────────────
Write-Host "[4/5] Patching service/main.js..."
$serviceFile = Join-Path $OUTPUT_DIR 'service\main.js'

if (-not (Test-Path $serviceFile)) {
    Write-Error "service/main.js not found at: $serviceFile"
    exit 1
}

$code = [IO.File]::ReadAllText($serviceFile)

# 4a. Cooldown Bypass (Structural Regex)
# Anchor: hàm validate license có dạng async f(arg){if(FLAG)return!0;if(!arg)return!1
$cooldownPat = 'async function\s+\w+\(\w+\)\{if\((\w+)\)return!0;if\(!\w+\)return!1'
if ($code -match $cooldownPat) {
    $cooldownVar = $Matches[1]
    $cooldownTarget = "${cooldownVar}=!1"
    if ($code.Contains($cooldownTarget)) {
        $code = $code.Replace($cooldownTarget, "${cooldownVar}=!0")
        Write-Host "      [OK] Cooldown bypass patched: ${cooldownVar}=!1 -> ${cooldownVar}=!0"
    } else {
        Write-Error "Cooldown target ${cooldownTarget} not found!"
        exit 1
    }
} else {
    Write-Error "Cooldown flag anchor function not found!"
    exit 1
}

# 4b. Bypass Premium Verification Function (Ty)
$tyPat = 'async function\s+(\w+)\((\w+)\)\{if\(\w+\)return!0;if\(!\2\)return!1;let\s+\w+=await\s+(\w+)\(\2\)'
if ($code -match $tyPat) {
    $tyFuncName = $Matches[1]
    $tyArg      = $Matches[2]
    $zFuncName  = $Matches[3]
    $code = [regex]::Replace($code, $tyPat, "async function ${tyFuncName}(${tyArg}){if(!${tyArg})return!1;return!0;if(jn)return!0;let dummy=await ${zFuncName}(${tyArg})")
    Write-Host "      [OK] Premium check function bypassed: ${tyFuncName}()"
} else {
    Write-Error "Premium verification function (Ty) not found!"
    exit 1
}

# 4c. Patch state getter dynamically to inject Premium JWT on runtime
$fakeJwtState = '{"store":"MICROSOFT","entitlement_type":"LIFETIME","valid_until":9999999999,"exp":9999999999,"developer":false,"user_id":1,"jti":"patched","iat":0,"raw":"placeholder.placeholder."}'
$jPat = 'function\s+(\w+)\(\)\{return\s+globalThis\._persistent_state\}'
if ($code -match $jPat) {
    $jFuncName = $Matches[1]
    $code = [regex]::Replace($code, $jPat, "function ${jFuncName}(){if(globalThis._persistent_state&&!globalThis._persistent_state.jwt){globalThis._persistent_state.jwt=${fakeJwtState}};return globalThis._persistent_state}")
    Write-Host "      [OK] State getter patched dynamically: ${jFuncName}()"
} else {
    Write-Error "State getter function returning globalThis._persistent_state not found!"
    exit 1
}

# 4d. Patch ID check in service/main.js dynamically
$idCheckPat = 'function\s+(\w+)\(\)\{[^{}]*return\s+\w+\|\|[^{}]*8817291756503653[^{}]*\}'
if ($code -match $idCheckPat) {
    $funcName = $Matches[1]
    $code = [regex]::Replace($code, $idCheckPat, "function ${funcName}(){return!0}")
    Write-Host "      [OK] ID check bypassed in service/main.js: ${funcName}()"
} else {
    Write-Error "ID check function not found in service/main.js!"
    exit 1
}

[IO.File]::WriteAllText($serviceFile, $code)


# ── STEP 5: Patch factory/factory.js ─────────────────────────────────────
$factoryFile = Join-Path $OUTPUT_DIR 'factory\factory.js'
if (Test-Path $factoryFile) {
    $fc = [IO.File]::ReadAllText($factoryFile)
    if ($fc -match $idCheckPat) {
        $funcName = $Matches[1]
        $fcFixed = [regex]::Replace($fc, $idCheckPat, "function ${funcName}(){return!0}")
        [IO.File]::WriteAllText($factoryFile, $fcFixed)
        Write-Host "      [OK] ID check bypassed in factory/factory.js: ${funcName}()"
    } else {
        Write-Error "ID check function not found in factory/factory.js!"
        exit 1
    }
} else {
    Write-Host "      [INFO] factory/factory.js not found, skipping"
}

# ── DONE ──────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "================================================================"
Write-Host " Done! Patched Video Download Helper v$extVersion is ready at:"
Write-Host " $OUTPUT_DIR"
Write-Host "================================================================"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Go to chrome://extensions or edge://extensions/ -> Enable Developer mode"
Write-Host "  2. Click 'Load unpacked' -> Select: $OUTPUT_DIR"
Write-Host ""
Write-Host "`nNOTICE: To update Video Download Helper when needed, please:" -ForegroundColor Cyan -BackgroundColor DarkGreen
Write-Host "1. Open PowerShell with Administrator privileges" -ForegroundColor White
Write-Host "2. Run the following command: irm https://go.bibica.net/vdh | iex" -ForegroundColor Yellow
Write-Host "3. Wait for the installation process to complete" -ForegroundColor White
pause
