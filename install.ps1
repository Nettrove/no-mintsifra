#Requires -Version 5.1
# One-line installer:  irm https://raw.githubusercontent.com/Nettrove/no-mintsifra/main/install.ps1 | iex
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$repo = 'Nettrove/no-mintsifra'
$arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }
$headers = @{ 'User-Agent' = 'no-mintsifra-installer' }
# A signed executable must carry this publisher's valid signature. Once every
# release is signed, $requireSignature turns a missing signature into a stop.
$expectedSigner = 'SignPath Foundation'
$requireSignature = $false

Write-Host 'no-mintsifra: ищу последний релиз...' -ForegroundColor Cyan
$release = Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest" -Headers $headers
$zip = $release.assets | Where-Object { $_.name -like "*windows-$arch.zip" } | Select-Object -First 1
$sums = $release.assets | Where-Object { $_.name -eq 'SHA256SUMS.txt' } | Select-Object -First 1
if (-not $zip -or -not $sums) { throw 'В релизе нет нужных файлов.' }

$work = Join-Path ([IO.Path]::GetTempPath()) ('no-mintsifra-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
try {
    $zipPath = Join-Path $work $zip.name
    Invoke-WebRequest $zip.browser_download_url -OutFile $zipPath -Headers $headers -UseBasicParsing
    $expected = ((Invoke-RestMethod $sums.browser_download_url -Headers $headers) -split "`n" |
        Where-Object { $_ -match [regex]::Escape($zip.name) } | Select-Object -First 1) -split '\s+' | Select-Object -First 1
    $actual = (Get-FileHash $zipPath -Algorithm SHA256).Hash
    if (-not $expected -or $actual -ne $expected.ToUpper()) { throw 'Контрольная сумма архива не совпала, установка остановлена.' }

    Expand-Archive $zipPath -DestinationPath $work -Force
    $exe = Get-ChildItem $work -Recurse -Filter 'no-mintsifra.exe' | Select-Object -First 1
    $sig = Get-AuthenticodeSignature $exe.FullName
    if ($sig.Status -eq 'Valid') {
        $signer = $sig.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
        if ($signer -ne $expectedSigner) { throw "Файл подписан не тем издателем ($signer), установка остановлена." }
    } elseif ($requireSignature -or $sig.Status -ne 'NotSigned') {
        throw "Подпись файла недействительна ($($sig.Status)), установка остановлена."
    }
    # The executable is windowless and opens its own console; wait for it to
    # finish. Start-Process -Wait would also wait for the proxy it leaves
    # running, so the wait is on this one process only.
    $p = Start-Process $exe.FullName -ArgumentList 'install', '-y' -PassThru
    $p.WaitForExit()
}
finally {
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}
