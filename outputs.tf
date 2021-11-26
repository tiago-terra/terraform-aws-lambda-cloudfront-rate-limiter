output "blacklist_ipset_name" {
  value = aws_wafv2_ip_set.rate_limit_blacklist.name
}

output "blacklist_ipset_id" {
  value = aws_wafv2_ip_set.rate_limit_blacklist.id
}
