echo ""
$install_dir = join-path $env:ProgramW6432 "Smallstep Labs"
echo "Installing step: '$install_dir'"
mkdir $install_dir >$null
echo ""
$exe_file = join-path $install_dir "step.exe"
curl.exe -L -o $exe_file https://files.smallstep.com/step-windows-${CLI_VERSION}.exe
$uninstall_file = join-path $install_dir "uninstall-step.ps1"
curl.exe -L -o $uninstall_file https://files.smallstep.com/uninstall-step.ps1
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
