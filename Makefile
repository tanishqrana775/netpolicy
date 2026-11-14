# ==============================================================================
# Netpolicy Automation Makefile
#
# Convenient targets for system bootstrapping, virtual environment setup,
# environment diagnostics, namespace lab management, and testing.
# ==============================================================================

.PHONY: setup-system setup-python doctor lab-up lab-down demo validate-quick validate-full test lint

# 1. System Package Setup
setup-system:
	@echo "Root privileges required to install system dependencies."
	@echo "Please run:"
	@echo "  sudo bash scripts/bootstrap-system.sh"

# 2. Python Virtual Environment Setup (runs as normal user)
setup-python:
	@bash scripts/bootstrap-python.sh

# 3. Environment Diagnostics
doctor:
	@bash scripts/doctor.sh

# 4. Start Namespace Lab (setup topology & start services)
lab-up:
	@if [ "$$(id -u)" -eq 0 ]; then \
		bash lab/setup.sh && bash lab/services.sh start; \
	else \
		echo "Root privileges required. Please run:"; \
		echo "  sudo bash lab/setup.sh"; \
		echo "  sudo bash lab/services.sh start"; \
	fi

# 5. Tear Down Namespace Lab
lab-down:
	@if [ "$$(id -u)" -eq 0 ]; then \
		bash lab/teardown.sh; \
	else \
		echo "Root privileges required. Please run:"; \
		echo "  sudo bash lab/teardown.sh"; \
	fi

# 6. End-to-End Demo (Baseline audit -> scenario -> tampered audit -> compare)
demo:
	@if [ "$$(id -u)" -eq 0 ]; then \
		bash scripts/demo.sh; \
	else \
		echo "Root privileges required. Please run:"; \
		echo "  sudo bash scripts/demo.sh"; \
	fi

# 7. Quick Ground-Truth Validation (5 runs per scenario)
validate-quick:
	@if [ "$$(id -u)" -eq 0 ]; then \
		if [ -x .linux-venv/bin/python ]; then \
			.linux-venv/bin/python lab/validate.py --runs 5; \
		elif [ -x .venv/bin/python ]; then \
			.venv/bin/python lab/validate.py --runs 5; \
		else \
			python3 lab/validate.py --runs 5; \
		fi; \
	else \
		echo "Root privileges required. Please run:"; \
		echo "  sudo .linux-venv/bin/python lab/validate.py --runs 5"; \
	fi

# 8. Full Ground-Truth Validation with tc netem sweeps (30 runs per scenario)
validate-full:
	@if [ "$$(id -u)" -eq 0 ]; then \
		if [ -x .linux-venv/bin/python ]; then \
			.linux-venv/bin/python lab/validate.py --runs 30 --netem; \
		elif [ -x .venv/bin/python ]; then \
			.venv/bin/python lab/validate.py --runs 30 --netem; \
		else \
			python3 lab/validate.py --runs 30 --netem; \
		fi; \
	else \
		echo "Root privileges required. Please run:"; \
		echo "  sudo .linux-venv/bin/python lab/validate.py --runs 30 --netem"; \
	fi

# 9. Run Unit Test Suite
test:
	@if [ -x .linux-venv/bin/pytest ]; then \
		.linux-venv/bin/pytest; \
	elif [ -x .venv/bin/pytest ]; then \
		.venv/bin/pytest; \
	else \
		pytest; \
	fi

# 10. Code Quality Linting & Type Checking
lint:
	@if [ -x .linux-venv/bin/python ]; then \
		.linux-venv/bin/python -m ruff check . && \
		.linux-venv/bin/python -m ruff format --check . && \
		.linux-venv/bin/python -m mypy netpolicy tests canary lab; \
	elif [ -x .venv/bin/python ]; then \
		.venv/bin/python -m ruff check . && \
		.venv/bin/python -m ruff format --check . && \
		.venv/bin/python -m mypy netpolicy tests canary lab; \
	else \
		ruff check . && ruff format --check . && mypy netpolicy tests canary lab; \
	fi
