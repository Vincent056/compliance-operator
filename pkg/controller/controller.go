package controller

import (
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/ComplianceAsCode/compliance-operator/pkg/controller/metrics"
	"github.com/ComplianceAsCode/compliance-operator/pkg/utils"
)

// AddToManagerFuncs is a list of functions to add all Controllers to the Manager
var AddToManagerFuncs []func(manager.Manager, *metrics.Metrics, utils.CtlplaneSchedulingInfo, *kubernetes.Clientset) error

// AddToManager adds all Controllers to the Manager
func AddToManager(m manager.Manager,
	met *metrics.Metrics,
	si utils.CtlplaneSchedulingInfo,
	kubeClient *kubernetes.Clientset,
) error {
	// Add metrics Startup to the manager
	if err := m.Add(met); err != nil {
		return err
	}

	for _, f := range AddToManagerFuncs {
		if err := f(m, met, si, kubeClient); err != nil {
			return err
		}
	}
	return nil
}
