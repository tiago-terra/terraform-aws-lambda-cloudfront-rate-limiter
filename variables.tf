variable "name" {
  type        = string
  description = "The name to assign to resources"
}

variable "log_level" {
  type        = string
  description = "The Lambda log level"
}

variable "cloudfront_logs_bucket_name" {
  type        = string
  description = "The Cloudfront Access logs bucket name"
}

variable "waf_blacklist_ipset_name" {
  type        = string
  description = "The WAFv2 blacklist IP Set Name"
}

variable "waf_rate_limit_blacklist_ips" {
  type        = list(string)
  description = "A list of IPs to add to the WAF IP Set for rate limiting blacklisting"
}

variable "waf_whitelist_ipset_name" {
  type        = string
  description = "The WAFv2 whitelist IP Set Name"
}

variable "max_request_rpm" {
  type        = number
  description = "The number of requests to accept per minute"
  default     = 50
}

variable "tags" {
  type        = map(any)
  description = "Any tags to associated with the resources"
  default     = {}
}
