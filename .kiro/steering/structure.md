# Repo layout
terraform/   main.tf iam.tf guardrail.tf budget.tf variables.tf outputs.tf
lambda/      handler.py extract.py prompts.py bedrock_client.py validate.py slack.py
tests/       fixtures/ (clean_*.json, inject_*.json)  test_unit.py  test_adversarial.py
results/     before_v1.json  after_v2.json  screenshots/
scripts/     run_suite.py
.github/workflows/  ci.yml  adversarial.yml
Rules: small functions, type hints, one responsibility per file, comments that explain WHY.
