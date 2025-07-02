/*
ID: a85b1291-0c1f-4b14-89c7-5b1929c7efc9
NAME: Impair Defenses: Disable or Modify Cloud Logs
TECHNIQUE: T1562.008
UNIT: response
CREATED: 2024-09-16 22:24:19.515445+00:00
*/
package main

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"

	Cloud "github.com/preludeorg/libraries/go/tests/cloud"
	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

var (
	cloudtrailArn string
	client        *cloudtrail.Client
)

func test() {
	ctx := context.TODO()
	client, err := Cloud.GetCloudTrailClient()
	if err != nil {
		Endpoint.Say("Got error \"%v\" when setting up CloudTrail client", err)
		Endpoint.Stop(Endpoint.NotRelevant)
	}

	result, err := client.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		Endpoint.Say("Got error \"%v\" when listing available Trails", err)
		Endpoint.Stop(Endpoint.NotRelevant)
	}

	for _, trail := range result.TrailList {
		stopLoggingInput := &cloudtrail.StopLoggingInput{
			Name: trail.TrailARN,
		}

		cloudtrailArn = *trail.TrailARN

		_, err = client.StopLogging(ctx, stopLoggingInput)
		if err != nil {
			Endpoint.Say("Got error \"%v\" when attempting to disable logging on trail with ARN \"%s\"", *trail.TrailARN, err)
			Endpoint.Stop(Endpoint.ExecutionPrevented)
		} else {
			Endpoint.Say("Successfully disabled logging on trail with ARN \"%s\"", *trail.TrailARN)
			Endpoint.Wait(1)
			Endpoint.Say("Reverting change")

			_, err := client.StartLogging(ctx, &cloudtrail.StartLoggingInput{
				Name: &cloudtrailArn,
			})
			if err != nil {
				Endpoint.Say("Got error \"%v\" when attempting to re-enable logging on trail with ARN \"%s\"", cloudtrailArn, err)
				Endpoint.Stop(Endpoint.CleanupFailed)
			} else {
				Endpoint.Say("Successfully re-enabled logging on trail with ARN \"%s\"", cloudtrailArn)
			}
			Endpoint.Stop(Endpoint.Unprotected)
		}

	}

	Endpoint.Say("No enumerable trails detected")
	Endpoint.Stop(Endpoint.NotRelevant)
}

func main() {
	Endpoint.Start(test)
}
