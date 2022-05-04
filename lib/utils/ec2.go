/*
Copyright 2021 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"context"
	"io"
	"regexp"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/gravitational/trace"
)

// GetEC2IdentityDocument fetches the PKCS7 RSA2048 InstanceIdentityDocument
// from the IMDS for this EC2 instance.
func GetEC2IdentityDocument() ([]byte, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, trace.Wrap(err)
	}
	imdsClient := imds.NewFromConfig(cfg)
	output, err := imdsClient.GetDynamicData(context.TODO(), &imds.GetDynamicDataInput{
		Path: "instance-identity/rsa2048",
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	iidBytes, err := io.ReadAll(output.Content)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := output.Content.Close(); err != nil {
		return nil, trace.Wrap(err)
	}
	return iidBytes, nil
}

// GetEC2NodeID returns the node ID to use for this EC2 instance when using
// Simplified Node Joining.
func GetEC2NodeID() (string, error) {
	// fetch the raw IID
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return "", trace.Wrap(err)
	}
	imdsClient := imds.NewFromConfig(cfg)
	output, err := imdsClient.GetInstanceIdentityDocument(context.TODO(), nil)
	if err != nil {
		return "", trace.Wrap(err)
	}
	return NodeIDFromIID(&output.InstanceIdentityDocument), nil
}

// EC2 Node IDs are {AWS account ID}-{EC2 resource ID} eg:
//   123456789012-i-1234567890abcdef0
// AWS account ID is always a 12 digit number, see
//   https://docs.aws.amazon.com/general/latest/gr/acct-identifiers.html
// EC2 resource ID is i-{8 or 17 hex digits}, see
//   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/resource-ids.html
var ec2NodeIDRE = regexp.MustCompile("^[0-9]{12}-i-[0-9a-f]{8,}$")

// IsEC2NodeID returns true if the given ID looks like an EC2 node ID
func IsEC2NodeID(id string) bool {
	return ec2NodeIDRE.MatchString(id)
}

// NodeIDFromIID returns the node ID that must be used for nodes joining with
// the given Instance Identity Document.
func NodeIDFromIID(iid *imds.InstanceIdentityDocument) string {
	return iid.AccountID + "-" + iid.InstanceID
}
