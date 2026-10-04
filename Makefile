# Convenience targets. The script needs no build step; this is for humans and
# for the self-test gate.
# SPDX-License-Identifier: 0BSD

.PHONY: test report check clean

test:
	@sh tests/selftest.sh

# Run against this host.
report:
	@sh sandprobe -o report.txt
	@echo "wrote report.txt ($$(wc -l < report.txt) lines)"

check:
	@for f in sandprobe lib/*.sh tests/*.sh; do sh -n "$$f" || exit 1; done
	@python3 -c "import ast,sys; ast.parse(open('lib/netprobe.py').read())"
	@echo "syntax OK"

clean:
	@rm -f report.txt a.txt b.txt sec-*.txt
	@find . -name '.sandprobe-*' -delete 2>/dev/null || true
