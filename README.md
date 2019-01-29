A Nagios plugin to report on AWS Config compliance status. Requires use of a Config Aggregator.

```
./check_aws_config_aggregator -config-aggregator-name config_aggregator -aws-region us-west-2
CRITICAL - Non-compliant resources detected in the following regions: required_tags=[ap-southeast-2,us-east-2]
```
