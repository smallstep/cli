echo ""
$step_path = step.exe path --base
if ( Test-Path -Path $step_path -PathType Container ) {
	$Confirm = Read-Host "Remove user configuration directory '$step_path'? [Y/N]"
	if ($Confirm -match 'y') {
		echo "Removing user configuration directory: '$step_path'"
		rm -R $step_path
	}
}
$install_dir = join-path $env:ProgramW6432 "Smallstep Labs"
echo "Uninstalling step: '$install_dir'"
rm -R $install_dir
echo 'Removing step.exe from the Machine $Path'
$path = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
$path = @($Env:Path.split(";") | where {$_ -ne $install_dir}) -join ";"
[System.Environment]::SetEnvironmentVariable("Path", $path, "Machine")
echo "Disabling ssh-agent..."
Stop-Service ssh-agent
Set-Service -Name ssh-agent -StartupType Disabled
Get-Service ssh-agent | Select Name, Status, StartType
echo ""
echo "Done!"
