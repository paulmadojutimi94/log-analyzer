# Everything runs with the standard library; pytest and ruff are only for development.
PY ?= python3
export PYTHONPATH := src

.PHONY: demo generate analyze test lint eval eval-check examples clean

demo: generate analyze          ## generate 10,000 entries and analyse them

generate:
	$(PY) -m log_analyzer generate -n 10000 --seed 42 -o data/app.log

analyze:
	$(PY) -m log_analyzer analyze data/app.log -o reports

test:
	$(PY) -m pytest -q

lint:
	ruff check . && ruff format --check .

eval:                            ## all evals (about a minute); rewrites the README table
	$(PY) evals/run_all.py

eval-check:                      ## fail if the README table doesn't match evals/results/
	$(PY) evals/run_all.py --check

examples: demo                   ## refresh the sample reports committed in examples/
	mkdir -p examples
	cp reports/report.md reports/report.html reports/report.json reports/quarantine.jsonl examples/
	head -n 40 data/app.log > examples/app.head.log

clean:
	rm -rf data reports .pytest_cache .ruff_cache
