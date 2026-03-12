.PHONY: init validate format plan apply destroy output clean deploy check

init:
	terraform init

validate:
	terraform validate

format:
	terraform fmt -recursive

plan:
	terraform plan -out=tfplan

apply:
	terraform apply tfplan

apply-auto:
	terraform apply -auto-approve

destroy:
	terraform destroy -auto-approve

output:
	@echo ""
	terraform output lab_summary
	@echo ""

clean:
	rm -f tfplan function_code.zip
	rm -rf .terraform

deploy: validate plan apply output

check: validate format

# Show specific outputs
web-ip:
	@terraform output -raw web_server_ip

bucket:
	@terraform output -raw vulnerable_bucket_name

function-url:
	@terraform output -raw cloud_function_url

run-url:
	@terraform output -raw cloud_run_url
