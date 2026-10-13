.PHONY: check test mapping-contract \
	grc-up grc-status grc-admin grc-admin-secret grc-verify grc-down grc-stop grc-destroy \
	grc-bootstrap grc-rotate-admin grc-token-refresh grc-bridge-check \
	grc-push-dry-run grc-push grc-push-verify grc-ledger-verify grc-summary grc-demo

PYTHON ?= python3
# Lab report for push and demo. A fresh one: REPORT=../mcp-svid-auth/deploy/.data/demo-report.json
REPORT ?= fixtures/lab/demo-report-2026-10-13.json
export PYTHONPATH := $(CURDIR)/src

check:
	$(PYTHON) -m unittest discover -s tests -v
	$(PYTHON) scripts/validate_repository.py

test: check

# Downloads the pinned upstream library into memory and checks every mapped URN (needs network).
mapping-contract:
	$(PYTHON) scripts/check_mapping_contract.py --download

# Dedicated it-grc Lima VM with CISO Assistant CE (docs/deployment.md).
grc-up:
	$(PYTHON) scripts/grc_lab.py up

grc-status:
	$(PYTHON) scripts/grc_lab.py status

grc-admin:
	$(PYTHON) scripts/grc_lab.py bootstrap-admin

grc-admin-secret:
	$(PYTHON) scripts/grc_lab.py sync-admin-secret

grc-verify:
	$(PYTHON) scripts/grc_lab.py verify

grc-down:
	$(PYTHON) scripts/grc_lab.py down

grc-stop:
	$(PYTHON) scripts/grc_lab.py stop

# Bridge into CISO Assistant (docs/bridge.md).
grc-bootstrap:
	$(PYTHON) -m it_grc bootstrap

grc-rotate-admin:
	$(PYTHON) -m it_grc rotate-admin

grc-token-refresh:
	$(PYTHON) -m it_grc token-refresh

grc-bridge-check:
	$(PYTHON) -m it_grc bridge-check

# Mapped lab evidence into the audit ITGRC-800-66R2 (docs/mapping.md).
grc-push-dry-run:
	$(PYTHON) -m it_grc push --report "$(REPORT)" --dry-run

grc-push:
	$(PYTHON) -m it_grc push --report "$(REPORT)"

grc-push-verify:
	$(PYTHON) -m it_grc verify

# Offline check of the local push ledger and its checkpoint (docs/bridge.md).
grc-ledger-verify:
	$(PYTHON) -m it_grc ledger verify

# Read-only audit summary: results, statuses, coverage, evidence and applied control.
grc-summary:
	$(PYTHON) -m it_grc summary

# End to end on an already bootstrapped instance (docs/demo.md). Stops at the first failure.
grc-demo:
	@echo "== 1/5 it-grc push --dry-run (report $(REPORT))"
	$(PYTHON) -m it_grc push --report "$(REPORT)" --dry-run
	@echo "== 2/5 it-grc push"
	$(PYTHON) -m it_grc push --report "$(REPORT)"
	@echo "== 3/5 it-grc verify"
	$(PYTHON) -m it_grc verify
	@echo "== 4/5 it-grc ledger verify"
	$(PYTHON) -m it_grc ledger verify
	@echo "== 5/5 it-grc summary"
	$(PYTHON) -m it_grc summary

# Deletes the VM and its data. Requires: make grc-destroy CONFIRM=yes
grc-destroy:
	$(PYTHON) scripts/grc_lab.py destroy $(if $(filter yes,$(CONFIRM)),--yes,)
