# Create install directory
echo ""
$install_dir = join-path $env:ProgramW6432 "Smallstep Labs"
echo "Installing step: '$install_dir'"
mkdir $install_dir >$null

# Determine filename to download
$response = Invoke-Webrequest -Uri "https://api.github.com/repos/smallstep/cli/releases/latest" -UseBasicParsing
$release = $response | ConvertFrom-Json

# Download the binary and uninstall script
echo ""
$exe_file = join-path $install_dir "step.exe"
curl.exe -L -o $exe_file "https://dl.smallstep.com/s3/cli/s3-windows-installer/step_latest_windows.exe"
$uninstall_file = join-path $install_dir "uninstall-step.ps1"
curl.exe -L -o $uninstall_file https://dl.smallstep.com/s3/cli/s3-windows-installer/uninstall-step.ps1
echo ""

echo 'Adding step.exe to the Machine $Path'
$path = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
$path = @($Env:Path.split(";") | where {$_ -ne $install_dir}) -join ";"
[System.Environment]::SetEnvironmentVariable("Path", $path + ";$install_dir", "Machine")

echo ""
echo "Enabling ssh-agent..."
Set-Service -Name ssh-agent -StartupType Automatic
Start-Service ssh-agent
Get-Service ssh-agent | Select Name, Status, StartType
echo ""
echo "Please restart shell sessions to pickup path changes."
