package main

import (
	"flag"
	"fmt"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	config "github.com/aws/aws-sdk-go/service/configservice"
	"github.com/jasonhancock/go-nagios"
	"github.com/pkg/errors"
)

func main() {
	p := nagios.NewPlugin("check_aws_config_aggregator", flag.CommandLine)
	p.StringFlag("config-aggregator-name", "", "Required. The configuration aggregator name.")
	p.StringFlag("aws-region", "", "Optional. The region the config aggregator resides in.")
	p.StringFlag("aws-access-key-id", "", "Optional. The AWS access key id.")
	p.StringFlag("aws-secret-key", "", "Optional. The AWS access key id.")
	flag.Parse()

	configAggregatorName := p.OptRequiredString("config-aggregator-name")
	awsRegion, _ := p.OptString("aws-region")
	awsAccessKeyID, _ := p.OptString("aws-access-key-id")
	awsSecretKey, _ := p.OptString("aws-secret-key")

	awsConfig := aws.NewConfig()
	if awsRegion != "" {
		awsConfig = awsConfig.WithRegion(awsRegion)
	}

	if awsAccessKeyID != "" && awsSecretKey != "" {
		awsConfig = awsConfig.WithCredentials(credentials.NewStaticCredentials(awsAccessKeyID, awsSecretKey, ""))
	}

	sess, err := session.NewSession(awsConfig)
	if err != nil {
		p.Fatal(errors.Wrap(err, "creating session"))
	}

	svc := config.New(sess)

	var next *string

	nonCompliant := make(map[string][]string)

	for {
		in := &config.DescribeAggregateComplianceByConfigRulesInput{
			ConfigurationAggregatorName: aws.String(configAggregatorName),
			NextToken:                   next,
		}
		out, err := svc.DescribeAggregateComplianceByConfigRules(in)
		if err != nil {
			p.Fatal(errors.Wrap(err, "retrieving aggregate compliance"))
		}

		for _, result := range out.AggregateComplianceByConfigRules {
			if result.Compliance == nil || *result.Compliance.ComplianceType != "NON_COMPLIANT" {
				continue
			}

			if _, ok := nonCompliant[*result.ConfigRuleName]; !ok {
				nonCompliant[*result.ConfigRuleName] = make([]string, 0, 1)
			}

			nonCompliant[*result.ConfigRuleName] = append(nonCompliant[*result.ConfigRuleName], *result.AwsRegion)
		}

		next = out.NextToken
		if next == nil {
			break
		}
	}

	code := nagios.OK
	message := "OK - No resources found out of compliance"
	if len(nonCompliant) > 0 {
		code = nagios.CRITICAL
		rules := make([]string, 0, len(nonCompliant))
		for k := range nonCompliant {
			rules = append(rules, k)
		}
		sort.Strings(rules)

		messages := make([]string, 0, len(nonCompliant))
		for _, rule := range rules {
			sort.Strings(nonCompliant[rule])
			messages = append(messages, fmt.Sprintf("%s=[%s]", rule, strings.Join(nonCompliant[rule], ",")))
		}

		message = "CRITICAL - Non-compliant resources detected in the following regions: " + strings.Join(messages, " ")
	}

	p.Exit(code, message)
}
