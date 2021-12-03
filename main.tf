
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

data "aws_s3_bucket" "selected" {
  bucket = var.cloudfront_logs_bucket_name
}

####################################
# IAM
####################################
data "aws_iam_policy_document" "this" {

  statement {
    sid    = "AllowAccessToCloudfrontLogsBucket"
    effect = "Allow"

    actions = [
      "s3:ListBucket"
    ]

    resources = [
      data.aws_s3_bucket.selected.arn
    ]
  }

  statement {
    sid    = "AllowAccessToCloudFrontBucketObjects"
    effect = "Allow"

    actions = [
      "s3:GetObject"
    ]

    resources = ["${data.aws_s3_bucket.selected.arn}/*"]
  }

  statement {
    sid    = "AllowAccessToWafIPSets"
    effect = "Allow"

    actions = [
      "wafv2:ListIPSets",
      "wafv2:GetIPSet",
      "wafv2:UpdateIPSet"
    ]

    resources = [
      "arn:aws:wafv2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:global/ipset/*"
    ]
  }
}

####################################
# WAF
####################################
resource "aws_wafv2_ip_set" "rate_limit_blacklist" {
  name               = var.waf_blacklist_ipset_name
  description        = "Cloudfront Rate Limiting Blacklist IPSet"
  scope              = "CLOUDFRONT"
  ip_address_version = "IPV4"
  addresses          = var.waf_rate_limit_blacklist_ips
}

####################################
# Lambda
####################################
module "lambda" {
  source = "terraform-aws-modules/lambda/aws"

  function_name      = "${var.name}-lambda"
  description        = "Cloudfront Rate Limiting Lambda"
  handler            = "main.lambda_handler"
  runtime            = "python3.8"
  source_path        = "${path.module}/lambda"
  policy_json        = data.aws_iam_policy_document.this.json
  attach_policy_json = true
  publish            = true

  environment_variables = {
    LOG_LEVEL                   = var.log_level
    MAX_REQUEST_RATE_PER_MINUTE = var.max_request_rpm
    WAF_BLACKLIST_IPSET_NAME    = var.waf_blacklist_ipset_name
    WAF_WHITELIST_IPSET_NAME    = var.waf_whitelist_ipset_name
  }

  allowed_triggers = {
    S3 = {
      service    = "s3"
      source_arn = data.aws_s3_bucket.selected.arn
    }
  }

  tags = var.tags
}

####################################
# S3 Event trigger
####################################
resource "aws_s3_bucket_notification" "this" {
  bucket = data.aws_s3_bucket.selected.id

  lambda_function {
    lambda_function_arn = module.lambda.lambda_function_arn
    events              = ["s3:ObjectCreated:*"]
  }
}
