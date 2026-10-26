output "lambda_function_name" {
  description = "Name of the triage Lambda function."
  value       = aws_lambda_function.triage.function_name
}

output "lambda_log_group_name" {
  description = "CloudWatch log group where the Lambda writes its logs."
  value       = aws_cloudwatch_log_group.lambda.name
}
