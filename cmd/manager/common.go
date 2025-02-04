package manager

import (
	"fmt"
	"os"
	"path/filepath"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"

	ocpcfgv1 "github.com/openshift/api/config/v1"
	mcfgv1 "github.com/openshift/api/machineconfiguration/v1"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
	runtimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	compapis "github.com/ComplianceAsCode/compliance-operator/pkg/apis"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
)

const (
	maxRetries                          = 15
	maxRetriesForTimestamp              = 3
	complianceOperatorMetricsSA         = "compliance-operator-metrics"
	complianceOperatorMetricsSecretName = "compliance-operator-metrics-token"
)

var cmdLog = logf.Log.WithName("cmd")

type complianceCrClient struct {
	client    runtimeclient.Client
	scheme    *runtime.Scheme
	recorder  record.EventRecorder
	clientset *kubernetes.Clientset
}

func (crclient *complianceCrClient) useEventRecorder(source string, config *rest.Config) error {
	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartEventWatcher(
		func(e *corev1.Event) {
			cmdLog.Info(e.Type, "object", e.InvolvedObject, "reason", e.Reason, "message", e.Message)
		})
	eventBroadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: kubeClient.CoreV1().Events("")})
	crclient.recorder = eventBroadcaster.NewRecorder(crclient.scheme, v1.EventSource{Component: source})
	return nil
}

func DeriveResourcePath(gvr schema.GroupVersionResource, namespace string) string {
	var objPath string
	if gvr.Group == "" {
		// Core resource like "namespaces"
		if namespace == "" {
			objPath = fmt.Sprintf("/api/%s/%s", gvr.Version, gvr.Resource)
		} else {
			objPath = fmt.Sprintf("/api/%s/namespaces/%s/%s", gvr.Version, namespace, gvr.Resource)
		}
	} else {
		// Non-core resource
		if namespace == "" {
			objPath = fmt.Sprintf("/apis/%s/%s/%s", gvr.Group, gvr.Version, gvr.Resource)
		} else {
			objPath = fmt.Sprintf("/apis/%s/%s/namespaces/%s/%s", gvr.Group, gvr.Version, namespace, gvr.Resource)
		}
	}
	return objPath
}

func (crclient *complianceCrClient) getClient() runtimeclient.Client {
	return crclient.client
}

func (crclient *complianceCrClient) getRecorder() record.EventRecorder {
	return crclient.recorder
}

func (crclient *complianceCrClient) getScheme() *runtime.Scheme {
	return crclient.scheme
}

func (crclient *complianceCrClient) getClientset() *kubernetes.Clientset {
	return crclient.clientset
}

func getScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()

	corev1.AddToScheme(scheme)
	mcfgv1.AddToScheme(scheme)
	compapis.AddToScheme(scheme)
	ocpcfgv1.AddToScheme(scheme)

	return scheme
}

func createCrClient(config *rest.Config) (*complianceCrClient, error) {
	scheme := getScheme()

	client, err := runtimeclient.New(config, runtimeclient.Options{
		Scheme: scheme,
	})
	if err != nil {
		return nil, err
	}

	clientSet, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return &complianceCrClient{
		client:    client,
		scheme:    scheme,
		clientset: clientSet,
	}, nil
}

func getValidStringArg(cmd *cobra.Command, name string) string {
	val, _ := cmd.Flags().GetString(name)
	if val == "" {
		fmt.Fprintf(os.Stderr, "The command line argument '%s' is mandatory.\n", name)
		os.Exit(1)
	}
	return val
}

func readContent(filename string) (*os.File, error) {
	// gosec complains that the file is passed through an evironment variable. But
	// this is not a security issue because none of the files are user-provided
	cleanFileName := filepath.Clean(filename)
	// #nosec G304
	return os.Open(cleanFileName)
}

// ResourceExists returns true if the given resource kind exists
// in the given api groupversion
func ResourceExists(dc discovery.DiscoveryInterface, apiGroupVersion, kind string) (bool, error) {

	_, apiLists, err := dc.ServerGroupsAndResources()
	if err != nil {
		return false, err
	}
	for _, apiList := range apiLists {
		if apiList.GroupVersion == apiGroupVersion {
			for _, r := range apiList.APIResources {
				if r.Kind == kind {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

var ErrServiceMonitorNotPresent = fmt.Errorf("no ServiceMonitor registered with the API")

type ServiceMonitorUpdater func(*monitoringv1.ServiceMonitor) error

// GenerateServiceMonitor generates a prometheus-operator ServiceMonitor object
// based on the passed Service object.
func GenerateServiceMonitor(s *corev1.Service) *monitoringv1.ServiceMonitor {
	labels := make(map[string]string)
	for k, v := range s.ObjectMeta.Labels {
		labels[k] = v
	}
	endpoints := populateEndpointsFromServicePorts(s)
	boolTrue := true

	return &monitoringv1.ServiceMonitor{
		ObjectMeta: metav1.ObjectMeta{
			Name:      s.ObjectMeta.Name,
			Namespace: s.ObjectMeta.Namespace,
			Labels:    labels,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         "v1",
					BlockOwnerDeletion: &boolTrue,
					Controller:         &boolTrue,
					Kind:               "Service",
					Name:               s.Name,
					UID:                s.UID,
				},
			},
		},
		Spec: monitoringv1.ServiceMonitorSpec{
			Selector: metav1.LabelSelector{
				MatchLabels: labels,
			},
			Endpoints: endpoints,
		},
	}
}

func populateEndpointsFromServicePorts(s *corev1.Service) []monitoringv1.Endpoint {
	var endpoints []monitoringv1.Endpoint
	for _, port := range s.Spec.Ports {
		endpoints = append(endpoints, monitoringv1.Endpoint{Port: port.Name})
	}
	return endpoints
}
