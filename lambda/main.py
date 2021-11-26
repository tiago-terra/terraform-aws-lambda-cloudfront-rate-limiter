"""
CloudFront Rate Limiter Lambda

1: Lambda is triggered after an entry is added to CloudFront access logs bucket
2: Lambda parses the log entries to retrieve the viewer IPs 
3: Lambda retrieves WAF IPSets for WAF rate limiting temporary Blacklist and WAF Whitelist
4: Lambda updates WAF rate limiting Blacklist IPSet with extracted viwer IPs (as long as IPs are not explicitely in WAF whitelist)
5: Lambda removes any IPs in Rate limiting Blacklist that are not present in the extracted logs

Example S3 event:
{
  "Records": [
    {
      "eventVersion": "2.1",
      "eventSource": "aws:s3",
      "awsRegion": "us-east-2",
      "eventTime": "2019-09-03T19:37:27.192Z",
      "eventName": "ObjectCreated:Put",
      "userIdentity": {
        "principalId": "AWS:AIDAINPONIXQXHT3IKHL2"
      },
      "requestParameters": {
        "sourceIPAddress": "205.255.255.255"
      },
      "responseElements": {
        "x-amz-request-id": "D82B88E5F771F645",
        "x-amz-id-2": "vlR7PnpV2Ce81l0PRw6jlUpck7Jo5ZsQjryTjKlc5aLWGVHPZLj5NeC6qMa0emYBDXOo6QBU0Wo="
      },
      "s3": {
        "s3SchemaVersion": "1.0",
        "configurationId": "828aa6fc-f7b5-4305-8584-487c791949c1",
        "bucket": {
          "name": "DOC-EXAMPLE-BUCKET",
          "ownerIdentity": {
            "principalId": "A3I5XTEXAMAI3E"
          },
          "arn": "arn:aws:s3:::lambda-artifacts-deafc19498e3f2df"
        },
        "object": {
          "key": "b21b84d653bb07b05b1e6b33684dc11b",
          "size": 1305107,
          "eTag": "b21b84d653bb07b05b1e6b33684dc11b",
          "sequencer": "0C0F6F405D6ED209E1"
        }
      }
    }
  ]
}
"""
import boto3, datetime, gzip, logging, json, os, re


class Logging():

    def __init__(self, testing=False):
        self.logger = logging.getLogger(__name__)
        self.log_level = os.environ.get("LOG_LEVEL", logging.INFO)
        self.logger.setLevel(self.log_level)

        if testing:
            logging.basicConfig()


class S3EventParser:

    def __init__(self, event, logger):
        self.event = event
        self.logger = logger

    def parse_event(self):
        """
        Outputs an object containing the S3 bucket and key from an upstream S3 Event
        """
        payload = json.loads(json.dumps(self.event))
        bucket_name = payload["Records"][0]["s3"]["bucket"]["name"] 
        bucket_object = payload["Records"][0]["s3"]["object"]["key"]
        output = {}

        if bucket_name and bucket_object not in None:
            self.logger.info(f"Extracted bucket {bucket_name} and bucket key {bucket_object} from S3 event object")
            output["name"] = bucket_name
            output["key"] = bucket_object
        else:
            logger.error("Error extracing bucket details from S3 event payload!")
        return output

class CloudfrontLogParser:

    def __init__(self, bucket_name, bucket_key, logger, limit_per_min=5):
        self.s3 = boto3.client("s3")
        self.logger = logger
        self.bucket_name = bucket_name
        self.bucket_key = bucket_key
        self.limit_per_min = limit_per_min

        log = self._get_object_data()
        parsed_log = self._parse_log_data(log)
        log_duration_seconds = self._get_log_timedeltas(parsed_log[0], parsed_log[-1])

        self.rate_per_minute = self._calculate_block_count(log_duration_seconds, limit_per_min)
        self.ips = self._get_ips(parsed_log)


    def _get_object_data(self):
        """
        Checks if the passed S3 object is a .gz extension (Cloudfront access log), and if so it returns an unparsed data object
        """
        response = self.s3.get_object(Bucket=self.bucket_name, Key=self.bucket_key)
        body = []

        if (re.match(".*.gz$", self.bucket_key)):
            body = gzip.decompress(response["Body"].read()).decode("utf-8","ignore").splitlines()
        return body

    def _parse_log(self, line):
        """
        Parses a CloudFront access log line by outputting an object with relevant extracted fields
        """
        lines = line.split("\t")
        if len(lines) > 25 and (re.match("[0-9]...-[0-9].-[0-9]." , lines[0])) and (re.match("[0-9].:[0-9].:[0-9]." , lines[1])):
            obj = {}
            obj["date"] = lines[0]
            obj["time"] = lines[1]
            obj["x_edge_location"] = lines[2]
            obj["sc_bytes"] = lines[3]
            obj["c_ip"] = lines[4]
            return obj


    def _parse_log_data(self, loglines):
        """
        Parses a raw CloudFront access log, looping through all relevant loglines
        """
        output = []
        for line in loglines:
            parsed_log = self._parse_log(line)
            if parsed_log is not None:
                output.append(parsed_log)
        return output

    def _extract_datetime_from_log(self, logline):
        log_date,log_time = logline["date"], logline["time"]
        date = datetime.datetime.strptime(f"{log_date} {log_time}", "%Y-%m-%d %H:%M:%S")
        return date

    def _get_log_timedeltas(self, first_log, last_log):
        first_timestamp = self._extract_datetime_from_log(first_log)
        last_timestamp = self._extract_datetime_from_log(last_log)
        return (last_timestamp - first_timestamp).total_seconds()

    def _calculate_block_count(self, duration, limit_per_min):
        block_count = (int(limit_per_min)/60) * duration
        self.logger.info(f"[Cloudfront Log Parser] - Will blacklist IPs with over {block_count} counts over {duration} seconds")
        return block_count

    def _parse_ip(self, ip):
        """
        Parses an IP by adding a network mask if it"s not already present in the IP
        """
        if not (re.match("./*[0-9][0-9]$", ip)):
            ip = "{}/32".format(ip)
        return ip

    def _get_ips(self, list_of_ips):
        ips = []
        for ip in list_of_ips:
            ips.append(ip["c_ip"])
        return ips

    def get_ips_over_threshold(self, list_of_ips):
        """
        Returns a list of unique IPs that have showed up in the access logs over a specified block_count amount
        """
        final_ips = []
        unique_ips = list(dict.fromkeys(set(list_of_ips)))

        for ip in unique_ips:
            if list_of_ips.count(ip) > self.rate_per_minute:
                parsed_ip = self._parse_ip(ip)
                final_ips.append(parsed_ip)

        joined_ips = ", ".join(final_ips)
        self.logger.info(f"[Cloudfront Log Parser] - IPs over threshold count of {self.limit_per_min}/requests per min: {joined_ips}")
        return final_ips


class WAF:

    def __init__(self, blacklist_ipset_name, whitelist_ipset_name, viewer_ips, logger):
        self.waf = boto3.client("wafv2")
        self.logger = logger
        self.blacklist_ipset_name = blacklist_ipset_name
        self.whitelist_ipset_name = whitelist_ipset_name
        self.ipsets = self.get_ipsets()

        ips = self.get_final_ipset_list(viewer_ips)
        self.update_ipset(blacklist_ipset_name, ips)

    def get_ipsets(self):
        """
        Gets blacklist and whitelist IPSet Objects from WAF
        """
        ipset_names = self.blacklist_ipset_name, self.whitelist_ipset_name
        response = self.waf.list_ip_sets(Scope ="CLOUDFRONT", Limit=100)
        ipsets = response["IPSets"]
        ipset_objects = {}

        for ipset in ipsets:
            if ipset["Name"] in ipset_names:
                ipset_name = ipset["Name"]
                ipset_objects[ipset_name] = ipset
                ipset = self.waf.get_ip_set( Name=ipset_name, Scope="CLOUDFRONT", Id=ipset["Id"])
                ipset_objects[ipset_name] = ipset["IPSet"]
                ipset_objects[ipset_name]["LockToken"] = ipset["LockToken"]

        joined_ipset_names = ", ".join(ipset_names)
        self.logger.info(f"[WAF] - Retrieved IPSet objects for IP Sets: {joined_ipset_names}")

        return ipset_objects

    def get_final_ipset_list(self, list_of_ips):
        whitelisted_ips = self.ipsets[self.whitelist_ipset_name]["Addresses"]
        ip_list = []
        for ip in list_of_ips:
            if ip not in whitelisted_ips:
                ip_list.append(ip)

        joined_ip_list = ",".join(ip_list)
        self.logger.info(f"[WAF] - Final IP list created: {joined_ip_list}")
        return ip_list

    def update_ipset(self, ipset_name, list_of_ips):
        ipset = self.ipsets[ipset_name]
        self.waf.update_ip_set(Name=ipset_name, Id=ipset["Id"], LockToken=ipset["LockToken"], Addresses=list_of_ips, Scope="CLOUDFRONT")

        joined_ip_list = ",".join(list_of_ips)
        self.logger.info(f"[WAF] - IPSet {ipset_name} updated with IPs: {joined_ip_list}")

def lambda_handler(event, context):
    # Environment variables
    WAF_BLACKLIST_IPSET_NAME = os.environ.get("WAF_BLACKLIST_IPSET_NAME")
    WAF_WHITELIST_IPSET_NAME = os.environ.get("WAF_WHITELIST_IPSET_NAME")
    MAX_REQUEST_RATE_PER_MINUTE = os.environ.get("MAX_REQUEST_RATE_PER_MINUTE")

    logger = Logging()

    # Event parser
    event_parser = S3EventParser(event)
    cloudfront_bucket = event_parser.parse_event()

    # Log parser
    log_parser = CloudfrontLogParser(cloudfront_bucket["name"], cloudfront_bucket["key"], MAX_REQUEST_RATE_PER_MINUTE, logger=logger.logger)
    ips = log_parser.get_ips_over_threshold(log_parser.ips)

    # Update WAF
    waf = WAF(WAF_BLACKLIST_IPSET_NAME, WAF_WHITELIST_IPSET_NAME, ips, logger=logger.logger)
    waf_ipsets = waf.get_ipsets()
    return json.dumps(waf_ipsets)