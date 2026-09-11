.PHONY: install test lint format tf-init tf-plan tf-apply tf-destroy baseline scan demo web validate
install:
	python -m pip install -e ".[dev,web]"
test:
	python -m pytest
lint:
	python -m ruff check .
	python -m ruff format --check .
format:
	python -m ruff format .
	terraform -chdir=terraform fmt -recursive
# Raw commands are documented too; Make is optional on Windows.
tf-init:
	terraform -chdir=terraform init
tf-plan:
	terraform -chdir=terraform plan
tf-apply:
	terraform -chdir=terraform apply
tf-destroy:
	terraform -chdir=terraform destroy
baseline:
	python -m drift_detector baseline
scan:
	python -m drift_detector scan
demo:
	python -m drift_detector demo
web:
	python -m drift_detector serve --demo
validate:
	bash scripts/validate.sh
