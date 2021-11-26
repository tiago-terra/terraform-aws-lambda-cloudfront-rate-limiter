# Terrafom AWS Lambda Cloudfront Rate Limiter

Deploys a Lambda which allows for the rate limiting of Cloudfront requests based on a given request rate per minute

## Requirements

| Name      | Version   |
| --------- | --------- |
| terraform | >= 0.15   |
| aws       | >= 3.39.0 |

## Providers

| Name | Version   |
| ---- | --------- |
| aws  | >= 3.39.0 |

## Inputs

| Name                         | Description                                                           | Type           | Default | Required |
| ---------------------------- | --------------------------------------------------------------------- | -------------- | ------- | :------: |
| cloudfront_logs_bucket_name  | The Cloudfront Access logs bucket name                                | `string`       | n/a     |   yes    |
| log_level                    | The Lambda log level                                                  | `string`       | n/a     |   yes    |
| max_request_rpm              | The number of requests to accept per minute                           | `number`       | `50`    |    no    |
| name                         | The name to assign to resources                                       | `string`       | n/a     |   yes    |
| tags                         | Any tags to associated with the resources                             | `map(any)`     | `{}`    |    no    |
| waf_blacklist_ipset_name     | The WAFv2 blacklist IP Set Name                                       | `string`       | n/a     |   yes    |
| waf_rate_limit_blacklist_ips | A list of IPs to add to the WAF IP Set for rate limiting blacklisting | `list(string)` | n/a     |   yes    |
| waf_whitelist_ipset_name     | The WAFv2 whitelist IP Set Name                                       | `string`       | n/a     |   yes    |

## Outputs

| Name                 | Description |
| -------------------- | ----------- |
| blacklist_ipset_id   | n/a         |
| blacklist_ipset_name | n/a         |
