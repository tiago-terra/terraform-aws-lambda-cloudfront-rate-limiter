provider "aws" {}

module "rate_litiming_lambda" {
  source = "../"

  cloudfront_logs_bucket_name  = "payme-dev-payme-dragon-dev-merchant-cloudfront-access"
  log_level                    = "INFO"
  max_request_rpm              = 30
  name                         = "terraform-module-example-rate-limiting"
  waf_rate_limit_blacklist_ips = ["1.1.1.0/32"]
  waf_blacklist_ipset_name     = "cloudfront-ratelimit-blacklist"
  waf_whitelist_ipset_name     = "cloudfront-ratelimit-whitelist"
  tags                         = {}
}
