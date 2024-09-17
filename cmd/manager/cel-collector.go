/*
Copyright © 2024 Red Hat Inc.

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
package manager

import (
	"context"
	"os"
	"strings"

	"k8s.io/apimachinery/pkg/runtime/schema"

	cmpv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"

	"github.com/ComplianceAsCode/compliance-operator/pkg/controller/common"
	"github.com/ComplianceAsCode/compliance-operator/pkg/utils"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	runtimeclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// For CEL content, Implements ResourceFetcher.
type celResourcesFetcher struct {
	resourceFetcherClients
	tailoredProfile string
	resources       []utils.ResourcePath
	found           map[string][]byte
}

func NewCELDataStreamResourceFetcher(scheme *runtime.Scheme, client runtimeclient.Client, clientSet *kubernetes.Clientset) ResourceFetcher {
	return &celResourcesFetcher{
		resourceFetcherClients: resourceFetcherClients{
			clientset: clientSet,
			client:    client,
			scheme:    scheme,
		},
	}
}

func (c *celResourcesFetcher) LoadSource(path string) error {
	// TODO: Implement this
	// We are going to need to decide how to import data to the operator
	// For now, we are going to use the cr object directly
	return nil
}

func (c *celResourcesFetcher) LoadTailoring(profileID string) error {
	// TODO: Implement this
	// We are going to need to decide how to import data to the operator
	// For now, we are going to use the cr object directly
	// We need to parse the tailored profile name from the profileID
	const tpPrefix = "xccdf_compliance.openshift.io_profile_"
	tailoredProfileName := strings.Split(profileID, tpPrefix)[1]
	c.tailoredProfile = tailoredProfileName
	return nil
}

func (c *celResourcesFetcher) SaveWarningsIfAny(warnings []string, outputFile string) error {
	// No warnings to persist
	if warnings == nil || len(warnings) == 0 {
		return nil
	}
	DBG("Persisting warnings to output file")
	warningsStr := strings.Join(warnings, "\n")
	err := os.WriteFile(outputFile, []byte(warningsStr), 0600)
	return err
}

func (c *celResourcesFetcher) SaveResources(to string) error {
	return saveResources(to, c.found)
}

func (c *celResourcesFetcher) FigureResources(profile string) error {
	namespace := os.Getenv("POD_NAMESPACE")

	// Initial set of resources to fetch
	found := []utils.ResourcePath{
		{
			ObjPath:  "/version",
			DumpPath: "/version",
		},
	}

	// If a tailored profile is provided, extract resource paths from the selected rules
	if c.tailoredProfile != "" {
		tp := &cmpv1alpha1.TailoredProfile{}
		tpKey := types.NamespacedName{Name: c.tailoredProfile, Namespace: namespace}
		err := c.resourceFetcherClients.client.Get(context.TODO(), tpKey, tp)
		if err != nil {
			return err
		}

		// Fetch selected rules from the tailored profile
		selectedRules, err := c.getSelectedRules(tp)
		if err != nil {
			return err
		}

		for _, rule := range selectedRules {
			DBG("Processing rule: %s\n", rule.Name)
			DBG("Rule inputs: %v\n", rule.Inputs)
			for _, input := range rule.Inputs {
				gvr := schema.GroupVersionResource{
					Group:    input.APIGroup,
					Version:  input.Version,
					Resource: input.Resource,
				}

				// Derive the resource path using the common function
				objPath := DeriveResourcePath(gvr, input.Namespace)

				found = append(found, utils.ResourcePath{
					ObjPath:  objPath,
					DumpPath: objPath + ".json",
				})
			}
		}
	}

	c.resources = found
	DBG("c.resources: %v\n", c.resources)
	return nil
}

func (c *celResourcesFetcher) getSelectedRules(tp *cmpv1alpha1.TailoredProfile) ([]*cmpv1alpha1.Rule, error) {
	// Initialize a slice to hold the selected rules
	var selectedRules []*cmpv1alpha1.Rule

	// Iterate over the rule selections: enableRules, disableRules, and manualRules
	for _, selection := range append(tp.Spec.EnableRules, append(tp.Spec.DisableRules, tp.Spec.ManualRules...)...) {
		// Check if the rule is already in the selectedRules slice
		for _, rule := range selectedRules {
			if rule.Name == selection.Name {
				return nil, common.NewNonRetriableCtrlError("Rule '%s' appears twice in selections (enableRules or disableRules or manualRules)", selection.Name)
			}
		}

		// Fetch the rule from the cluster
		rule := &cmpv1alpha1.Rule{}
		ruleKey := types.NamespacedName{Name: selection.Name, Namespace: tp.Namespace}
		err := c.resourceFetcherClients.client.Get(context.TODO(), ruleKey, rule)
		if err != nil {
			if kerrors.IsNotFound(err) {
				return nil, common.NewNonRetriableCtrlError("Fetching rule: %w", err)
			}
			return nil, err
		}

		// Add the rule to the selectedRules slice
		selectedRules = append(selectedRules, rule)
	}

	return selectedRules, nil
}

func (c *celResourcesFetcher) FetchResources() ([]string, error) {
	found, warnings, err := fetch(context.Background(), getStreamerFn, c.resourceFetcherClients, c.resources)
	if err != nil {
		return warnings, err
	}
	// print the found resources
	for k, v := range found {
		LOG("Found resource: %s\n", k)
		LOG("Resource content: %s\n", v)
	}
	c.found = found
	return warnings, nil
}
