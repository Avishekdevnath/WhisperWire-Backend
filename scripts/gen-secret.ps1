Param(
  [int]$Bytes = 48
)

$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$buf = New-Object byte[] $Bytes
$rng.GetBytes($buf)
[Convert]::ToBase64String($buf)


