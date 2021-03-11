#!/bin/sh

if [ "$1" = "configure" ]; then
	if [ -f /usr/share/bash-completion/completions/step-cli ]; then
		update-alternatives \
			--install /usr/bin/step step /usr/bin/step-cli 50 \
			--slave /usr/share/bash-completion/completions/step step.bash-completion /usr/share/bash-completion/completions/step-cli
	fi
	if [ -f /etc/bash_completion.d/step-cli ]; then
		update-alternatives \
			--install /usr/bin/step step /usr/bin/step-cli 50 \
			--slave /etc/bash_completion.d/step step.bash-completion /etc/bash_completion.d/step-cli
	fi
fi
