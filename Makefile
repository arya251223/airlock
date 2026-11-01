.PHONY: install image run run-dev test test-docker ui-test report bench

install:            ## install Python dependencies
	pip install -r requirements-dev.txt

image:              ## build the hardened runner image used for every execution
	docker build -f docker/runner.Dockerfile -t airlock-runner:latest .

run: image          ## production-style: Docker backend on http://localhost:8000
	SANDBOX_BACKEND=docker uvicorn app.main:app --port 8000

run-dev:            ## no Docker needed (Linux only, NOT a security boundary)
	SANDBOX_BACKEND=process uvicorn app.main:app --reload --port 8000

test:               ## whole suite against the process backend
	SANDBOX_BACKEND=process python -m unittest discover -s tests -t . -v

test-docker: image  ## same suite against real Docker containers
	SANDBOX_BACKEND=docker python -m unittest discover -s tests -t . -v

ui-test:            ## headless-browser checks (server must be running on :8000)
	python -m tests.ui_check http://127.0.0.1:8000

report:             ## Markdown table of every payload vs. the configured backend
	python -m scripts.containment_report

bench:              ## latency / throughput numbers for the configured backend
	python -m scripts.benchmark
