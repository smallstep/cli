#!/bin/sh

updateAlternatives() {
	update-alternatives --install /usr/bin/step step /usr/bin/step-cli 50
}

updateCompletion() {
  /usr/bin/step completion bash > /usr/share/bash-completion/completions/step
  chmod 644 /usr/share/bash-completion/completions/step
}

cleanInstall() {
	updateAlternatives
	updateCompletion
}

upgrade() {
	updateAlternatives
	updateCompletion
}

action="$1"
if [ "$1" = "configure" ] && [ -z "$2" ]; then
	action="install"
elif [ "$1" = "configure" ] && [ -n "$2" ]; then
	action="upgrade"
fi

case "$action" in
	"1" | "install")
		cleanInstall
		;;
	"2" | "upgrade")
		upgrade
		;;
	*)
		cleanInstall
		;;
esac
