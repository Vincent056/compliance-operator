package compliancescan

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/pkg/controller/common"
	"github.com/ComplianceAsCode/compliance-operator/pkg/controller/metrics"
	"github.com/ComplianceAsCode/compliance-operator/pkg/controller/metrics/metricsfakes"
	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kube "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	restclient "k8s.io/client-go/rest/fake"
	"sigs.k8s.io/controller-runtime/pkg/client"
	runtimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func createFakeScanPods(reconciler ReconcileComplianceScan, scanName string, nodeNames ...string) {
	for _, nodeName := range nodeNames {
		podName1 := fmt.Sprintf("%s-%s-pod", scanName, nodeName)
		reconciler.Client.Create(context.TODO(), &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      podName1,
				Namespace: common.GetComplianceOperatorNamespace(),
			},
		})
	}
}

func createFakeRsSecret(reconciler ReconcileComplianceScan, scanName string) {
	// simulate result server secret as one of the resources that is cleaned up
	// based on the value of the doDelete flag
	secretName := fmt.Sprintf("%s%s", ServerCertPrefix, scanName)
	reconciler.Client.Create(context.TODO(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: common.GetComplianceOperatorNamespace(),
		},
	})
}

func createFakeKubletConfigCM(reconciler ReconcileComplianceScan, scanInstance *compv1alpha1.ComplianceScan, nodeinstance *corev1.Node) {
	// simulate kubelet config cm as one of the resources that is cleaned up
	// based on the value of the doDelete flag
	cmName := getKubeletCMNameForScan(scanInstance, nodeinstance)
	reconciler.Client.Create(context.TODO(), &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cmName,
			Namespace: common.GetComplianceOperatorNamespace(),
			Labels: map[string]string{
				compv1alpha1.ComplianceScanLabel: scanInstance.Name,
				compv1alpha1.KubeletConfigLabel:  "",
			},
		},
	})
}

var _ = Describe("Testing compliancescan controller phases", func() {

	var (
		compliancescaninstance *compv1alpha1.ComplianceScan
		handler                scanTypeHandler
		reconciler             ReconcileComplianceScan
		logger                 logr.Logger
		nodeinstance1          *corev1.Node
		nodeinstance2          *corev1.Node
	)

	BeforeEach(func() {
		// Uncomment these lines if you need to debug the controller's output.
		// dev, _ := zap.NewDevelopment()
		// logger = zapr.NewLogger(dev)
		logger = zapr.NewLogger(zap.NewNop())
		objs := []runtime.Object{}

		// test instance
		compliancescaninstance = &compv1alpha1.ComplianceScan{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test",
			},
			Spec: compv1alpha1.ComplianceScanSpec{
				ScanType:    compv1alpha1.ScanTypeNode,
				ScannerType: compv1alpha1.ScannerTypeOpenSCAP,
				ComplianceScanSettings: compv1alpha1.ComplianceScanSettings{
					RawResultStorage: compv1alpha1.RawResultStorageSettings{
						PVAccessModes: defaultAccessMode,
						Size:          compv1alpha1.DefaultRawStorageSize,
					},
				},
			},
		}
		objs = append(objs, compliancescaninstance)

		// Nodes in the deployment
		nodeinstance1 = &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "node-1",
				Labels: map[string]string{"kubernetes.io/os": "linux"},
			},
		}
		nodeinstance2 = &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "node-2",
				Labels: map[string]string{"kubernetes.io/os": "linux"},
			},
		}

		// Create a fake rest client to mock /api/v1/nodes/$nodeName/proxy/configz call

		restFake := &restclient.RESTClient{
			Client: restclient.CreateHTTPClient(func(req *http.Request) (*http.Response, error) {
				if req.URL.Path == "/api/v1/nodes/"+nodeinstance1.Name+"/proxy/configz" {
					return &http.Response{
						StatusCode: 200,
						Body:       ioutil.NopCloser(bytes.NewBuffer([]byte(`{"kubeletconfig": {"kind": "KubeletConfiguration", "apiVersion": "kubelet.config.k8s.io/v1beta1", "authentication": {"x509": {"clientCAFile": "/etc/kubernetes/ca.crt"}}}}`))),
					}, nil
				}
				if req.URL.Path == "/api/v1/nodes/"+nodeinstance2.Name+"/proxy/configz" {
					return &http.Response{
						StatusCode: 200,
						Body:       ioutil.NopCloser(bytes.NewBuffer([]byte(`{"kubeletconfig": {"kind": "KubeletConfiguration", "apiVersion": "kubelet.config.k8s.io/v1beta1"}}`))),
					}, nil
				}
				return &http.Response{
					StatusCode: 404,
					Body:       ioutil.NopCloser(bytes.NewBuffer([]byte(`{"error": "not found"}`))),
				}, nil
			}),
		}

		kubeClient := kube.New(restFake)
		caSecret, _ := makeCASecret(compliancescaninstance, common.GetComplianceOperatorNamespace())
		serverSecret, _ := serverCertSecret(compliancescaninstance, caSecret.Data[corev1.TLSCertKey], caSecret.Data[corev1.TLSPrivateKeyKey], common.GetComplianceOperatorNamespace())
		clientSecret, _ := clientCertSecret(compliancescaninstance, caSecret.Data[corev1.TLSCertKey], caSecret.Data[corev1.TLSPrivateKeyKey], common.GetComplianceOperatorNamespace())

		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: common.GetComplianceOperatorNamespace(),
			},
		}

		objs = append(objs, nodeinstance1, nodeinstance2, caSecret, serverSecret, clientSecret, ns)
		scheme := scheme.Scheme
		scheme.AddKnownTypes(compv1alpha1.SchemeGroupVersion, compliancescaninstance)

		statusObjs := []runtimeclient.Object{}
		statusObjs = append(statusObjs, compliancescaninstance)

		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithStatusSubresource(statusObjs...).
			WithRuntimeObjects(objs...).
			Build()

		var err error
		mockMetrics := metrics.NewMetrics(&metricsfakes.FakeImpl{})
		err = mockMetrics.Register()
		Expect(err).To(BeNil())

		reconciler = ReconcileComplianceScan{Client: client, ClientSet: kubeClient, Scheme: scheme, Metrics: mockMetrics}
		handler, err = getScanTypeHandler(&reconciler, compliancescaninstance, logger)
		Expect(err).To(BeNil())
		_, err = handler.validate()
		Expect(err).To(BeNil())
	})

	Context("On validations", func() {
		Context("With missing phase", func() {
			It("should update the compliancescan phase to pending", func() {
				cont, err := reconciler.validate(compliancescaninstance, logger)
				Expect(cont).To(BeFalse())
				Expect(err).To(BeNil())

				scan := &compv1alpha1.ComplianceScan{}
				key := types.NamespacedName{
					Name:      compliancescaninstance.Name,
					Namespace: compliancescaninstance.Namespace,
				}
				err = reconciler.Client.Get(context.TODO(), key, scan)
				Expect(err).To(BeNil())
				Expect(scan.Status.Phase).To(Equal(compv1alpha1.PhasePending))
			})
		})
		Context("With missing RawResultStorage.Size", func() {
			It("should update the compliancescan instance with the default size", func() {
				compliancescaninstance.Spec.RawResultStorage.Size = ""
				compliancescaninstance.Status.Phase = "PENDING"
				cont, err := reconciler.validate(compliancescaninstance, logger)
				Expect(cont).To(BeFalse())
				Expect(err).To(BeNil())

				scan := &compv1alpha1.ComplianceScan{}
				key := types.NamespacedName{
					Name:      compliancescaninstance.Name,
					Namespace: compliancescaninstance.Namespace,
				}
				err = reconciler.Client.Get(context.TODO(), key, scan)
				Expect(err).To(BeNil())
				Expect(scan.Spec.RawResultStorage.Size).To(Equal(compv1alpha1.DefaultRawStorageSize))
			})
		})

		Context("With invalid RawResultStorage.Size", func() {
			It("report an error and move to phase DONE", func() {
				compliancescaninstance.Spec.RawResultStorage.Size = "invalid"
				compliancescaninstance.Status.Phase = "PENDING"
				cont, err := reconciler.validate(compliancescaninstance, logger)
				Expect(cont).To(BeFalse())
				Expect(err).To(BeNil())

				scan := &compv1alpha1.ComplianceScan{}
				key := types.NamespacedName{
					Name:      compliancescaninstance.Name,
					Namespace: compliancescaninstance.Namespace,
				}
				err = reconciler.Client.Get(context.TODO(), key, scan)
				Expect(err).To(BeNil())
				Expect(scan.Status.Phase).To(Equal(compv1alpha1.PhaseDone))
				Expect(scan.Status.Result).To(Equal(compv1alpha1.ResultError))
			})
		})
	})
	Context("On the PENDING phase", func() {
		It("should update the compliancescan instance to phase LAUNCHING", func() {
			result, err := reconciler.phasePendingHandler(compliancescaninstance, logger)
			Expect(result).NotTo(BeNil())
			Expect(err).To(BeNil())
			Expect(compliancescaninstance.Status.Phase).To(Equal(compv1alpha1.PhaseLaunching))
			Expect(compliancescaninstance.Status.Result).To(Equal(compv1alpha1.ResultNotAvailable))
		})

		Context("With correct custom RawResultStorage.Size", func() {
			It("should update the compliancescan instance to phase LAUNCHING", func() {
				compliancescaninstance.Spec.RawResultStorage.Size = "2Gi"
				result, err := reconciler.phasePendingHandler(compliancescaninstance, logger)
				Expect(result).NotTo(BeNil())
				Expect(err).To(BeNil())
				Expect(compliancescaninstance.Status.Phase).To(Equal(compv1alpha1.PhaseLaunching))
				Expect(compliancescaninstance.Status.Result).To(Equal(compv1alpha1.ResultNotAvailable))
			})
		})

	})

	Context("On the LAUNCHING phase", func() {
		BeforeEach(func() {
			// Set state to RUNNING
			compliancescaninstance.Status.Phase = compv1alpha1.PhaseLaunching
			compliancescaninstance.Status.StartTimestamp = &metav1.Time{Time: time.Now()}
			err := reconciler.Client.Status().Update(context.TODO(), compliancescaninstance)
			Expect(err).To(BeNil())
		})
		Context("With no PVC", func() {
			It("should create PVC and stay on the same phase", func() {
				result, err := reconciler.phaseLaunchingHandler(handler, logger)
				Expect(result).ToNot(BeNil())
				Expect(err).To(BeNil())
				Expect(compliancescaninstance.Status.Phase).To(Equal(compv1alpha1.PhaseLaunching))

				// We should have scheduled a pod per node
				scan := &compv1alpha1.ComplianceScan{}
				key := types.NamespacedName{
					Name:      compliancescaninstance.Name,
					Namespace: compliancescaninstance.Namespace,
				}
				err = reconciler.Client.Get(context.TODO(), key, scan)
				Expect(err).To(BeNil())
				Expect(scan.Status.ResultsStorage.Name).To(Equal(getPVCForScanName(key.Name)))
			})
		})

		Context("With the PVC set and no Kubelet ConfigMap", func() {
			BeforeEach(func() {
				compliancescaninstance.Status.ResultsStorage.Name = getPVCForScanName(compliancescaninstance.Name)
				compliancescaninstance.Status.ResultsStorage.Namespace = common.GetComplianceOperatorNamespace()
				err := reconciler.Client.Status().Update(context.TODO(), compliancescaninstance)
				Expect(err).To(BeNil())
			})
			It("should create ConfigMap and go to phase RUNNING", func() {
				result, err := reconciler.phaseLaunchingHandler(handler, logger)
				Expect(result).ToNot(BeNil())
				Expect(err).To(BeNil())
				Expect(compliancescaninstance.Status.Phase).To(Equal(compv1alpha1.PhaseRunning))
				// Check if Kubelet ConfigMap was created
				cm := &corev1.ConfigMap{}
				cmKey := types.NamespacedName{
					Name:      getKubeletCMNameForScan(compliancescaninstance, nodeinstance1),
					Namespace: compliancescaninstance.Namespace,
				}
				err = reconciler.Client.Get(context.TODO(), cmKey, cm)
				Expect(err).To(BeNil())
				Expect(cm.Data[KubeletConfigMapName]).To(Equal(`{"kubeletconfig": {"kind": "KubeletConfiguration", "apiVersion": "kubelet.config.k8s.io/v1beta1", "authentication": {"x509": {"clientCAFile": "/etc/kubernetes/ca.crt"}}}}`))
				cmKey = types.NamespacedName{
					Name:      getKubeletCMNameForScan(compliancescaninstance, nodeinstance2),
					Namespace: compliancescaninstance.Namespace,
				}
				err = reconciler.Client.Get(context.TODO(), cmKey, cm)
				Expect(err).To(BeNil())
				Expect(cm.Data[KubeletConfigMapName]).To(Equal(`{"kubeletconfig": {"kind": "KubeletConfiguration", "apiVersion": "kubelet.config.k8s.io/v1beta1"}}`))
			})
		})

		Context("with the PVC set", func() {
			BeforeEach(func() {
				compliancescaninstance.Status.ResultsStorage.Name = getPVCForScanName(compliancescaninstance.Name)
				compliancescaninstance.Status.ResultsStorage.Namespace = common.GetComplianceOperatorNamespace()
				err := reconciler.Client.Status().Update(context.TODO(), compliancescaninstance)
				Expect(err).To(BeNil())
			})
			It("should update the compliancescan instance to phase RUNNING", func() {
				result, err := reconciler.phaseLaunchingHandler(handler, logger)
				Expect(result).ToNot(BeNil())
				Expect(err).To(BeNil())
				Expect(compliancescaninstance.Status.Phase).To(Equal(compv1alpha1.PhaseRunning))
			})
		})
	})

	Context("On the RUNNING phase", func() {
		Context("With no pods in the cluster", func() {
			It("should update the compliancescan instance to phase LAUNCHING", func() {
				result, err := reconciler.phaseRunningHandler(handler, logger)
				Expect(result).ToNot(BeNil())
				Expect(err).To(BeNil())
				Expect(compliancescaninstance.Status.Phase).To(Equal(compv1alpha1.PhaseLaunching))
			})
		})

		Context("With two pods in the cluster", func() {
			BeforeEach(func() {
				// Create the pods for the test
				podName1 := getPodForNodeName(compliancescaninstance.Name, nodeinstance1.Name)
				reconciler.Client.Create(context.TODO(), &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      podName1,
						Namespace: common.GetComplianceOperatorNamespace(),
					},
				})

				podName2 := getPodForNodeName(compliancescaninstance.Name, nodeinstance2.Name)
				reconciler.Client.Create(context.TODO(), &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      podName2,
						Namespace: common.GetComplianceOperatorNamespace(),
					},
				})

				err := reconciler.Client.Update(context.TODO(), compliancescaninstance)
				Expect(err).To(BeNil())

				// Set state to RUNNING
				compliancescaninstance.Status.Phase = compv1alpha1.PhaseRunning
				err = reconciler.Client.Status().Update(context.TODO(), compliancescaninstance)
				Expect(err).To(BeNil())
			})

			It("should stay in RUNNING state", func() {
				result, err := reconciler.phaseRunningHandler(handler, logger)
				Expect(err).To(BeNil())
				Expect(result).ToNot(BeNil())

				pods := &corev1.PodList{}
				err = reconciler.Client.List(context.TODO(), pods)
				Expect(err).To(BeNil())
				Expect(compliancescaninstance.Status.Phase).To(Equal(compv1alpha1.PhaseRunning))
			})
		})

		Context("With two pods that succeeded in the cluster", func() {
			BeforeEach(func() {
				// Create the pods for the test
				podName1 := getPodForNodeName(compliancescaninstance.Name, nodeinstance1.Name)
				reconciler.Client.Create(context.TODO(), &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      podName1,
						Namespace: common.GetComplianceOperatorNamespace(),
					},
					Status: corev1.PodStatus{
						Phase: corev1.PodSucceeded,
					},
				})

				podName2 := getPodForNodeName(compliancescaninstance.Name, nodeinstance2.Name)
				reconciler.Client.Create(context.TODO(), &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      podName2,
						Namespace: common.GetComplianceOperatorNamespace(),
					},
					Status: corev1.PodStatus{
						Phase: corev1.PodSucceeded,
					},
				})

				err := reconciler.Client.Update(context.TODO(), compliancescaninstance)
				Expect(err).To(BeNil())

				// Set state to RUNNING
				compliancescaninstance.Status.Phase = compv1alpha1.PhaseRunning
				err = reconciler.Client.Status().Update(context.TODO(), compliancescaninstance)
				Expect(err).To(BeNil())
			})

			It("should move to AGGREGATING state", func() {
				result, err := reconciler.phaseRunningHandler(handler, logger)
				Expect(result).ToNot(BeNil())
				Expect(err).To(BeNil())
				Expect(compliancescaninstance.Status.Phase).To(Equal(compv1alpha1.PhaseAggregating))
			})
		})
	})

	Context("On the DONE phase", func() {
		Context("with delete flag off", func() {
			BeforeEach(func() {
				// Create the pods and the secret for the test
				createFakeScanPods(reconciler, compliancescaninstance.Name, nodeinstance1.Name, nodeinstance2.Name)
				createFakeRsSecret(reconciler, compliancescaninstance.Name)

				// Set state to DONE
				compliancescaninstance.Status.Phase = compv1alpha1.PhaseDone
				err := reconciler.Client.Status().Update(context.TODO(), compliancescaninstance)
				Expect(err).To(BeNil())
			})
			It("Should return success & preserve resources", func() {
				result, err := reconciler.phaseDoneHandler(handler, compliancescaninstance, logger, dontDelete)
				Expect(err).To(BeNil())
				Expect(result).ToNot(BeNil())

				// scan pods are cleaned up regardless
				var pods corev1.PodList
				err = reconciler.Client.List(context.TODO(), &pods)
				Expect(err).To(BeNil())
				Expect(pods.Items).To(BeEmpty())

				// but other resources should be preserved
				var secrets corev1.SecretList
				err = reconciler.Client.List(context.TODO(), &secrets)
				Expect(err).To(BeNil())
				Expect(secrets.Items).ToNot(BeEmpty())
			})
		})
		Context("with delete flag on", func() {
			BeforeEach(func() {
				// Create the pods and the secret for the test
				createFakeScanPods(reconciler, compliancescaninstance.Name, nodeinstance1.Name, nodeinstance2.Name)
				createFakeRsSecret(reconciler, compliancescaninstance.Name)
				createFakeKubletConfigCM(reconciler, compliancescaninstance, nodeinstance1)
				createFakeKubletConfigCM(reconciler, compliancescaninstance, nodeinstance2)

				// Set state to DONE
				compliancescaninstance.Status.Phase = compv1alpha1.PhaseDone
				err := reconciler.Client.Status().Update(context.TODO(), compliancescaninstance)
				Expect(err).To(BeNil())
			})
			It("Should return success & clean up resources", func() {
				result, err := reconciler.phaseDoneHandler(handler, compliancescaninstance, logger, doDelete)
				Expect(err).To(BeNil())
				Expect(result).ToNot(BeNil())

				var pods corev1.PodList
				err = reconciler.Client.List(context.TODO(), &pods)
				Expect(err).To(BeNil())
				Expect(pods.Items).To(BeEmpty())

				// also other resources should be gone
				var secrets corev1.SecretList
				err = reconciler.Client.List(context.TODO(), &secrets)
				Expect(err).To(BeNil())
				Expect(secrets.Items).To(BeEmpty())

				var kubeletConfigCM corev1.ConfigMapList
				err = reconciler.Client.List(context.TODO(), &kubeletConfigCM, &client.ListOptions{
					LabelSelector: labels.SelectorFromSet(map[string]string{
						compv1alpha1.KubeletConfigLabel: "",
					}),
				})
				Expect(err).To(BeNil())
				Expect(kubeletConfigCM.Items).To(BeEmpty())

			})
		})
		Context("with delete flag off but debug on as well", func() {
			BeforeEach(func() {
				// Create the pods for the test
				createFakeScanPods(reconciler, compliancescaninstance.Name, nodeinstance1.Name, nodeinstance2.Name)
				createFakeRsSecret(reconciler, compliancescaninstance.Name)

				// Set state to DONE
				compliancescaninstance.Status.Phase = compv1alpha1.PhaseDone
				err := reconciler.Client.Status().Update(context.TODO(), compliancescaninstance)
				Expect(err).To(BeNil())
				compliancescaninstance.Spec.Debug = true
				err = reconciler.Client.Update(context.TODO(), compliancescaninstance)
				Expect(err).To(BeNil())
			})
			It("Should return success & not delete the scan pods or secrets (doDelete=false)", func() {
				result, err := reconciler.phaseDoneHandler(handler, compliancescaninstance, logger, dontDelete)
				Expect(err).To(BeNil())
				Expect(result).ToNot(BeNil())

				var pods corev1.PodList
				err = reconciler.Client.List(context.TODO(), &pods)
				Expect(err).To(BeNil())
				Expect(pods.Items).ToNot(BeEmpty())

				var secrets corev1.SecretList
				err = reconciler.Client.List(context.TODO(), &secrets)
				Expect(err).To(BeNil())
				Expect(secrets.Items).ToNot(BeEmpty())
			})
		})
		Context("with delete flag on but debug on as well", func() {
			BeforeEach(func() {
				// Create the pods for the test
				createFakeScanPods(reconciler, compliancescaninstance.Name, nodeinstance1.Name, nodeinstance2.Name)
				createFakeRsSecret(reconciler, compliancescaninstance.Name)

				// Set state to DONE
				compliancescaninstance.Status.Phase = compv1alpha1.PhaseDone
				compliancescaninstance.Spec.Debug = true
				err := reconciler.Client.Status().Update(context.TODO(), compliancescaninstance)
				Expect(err).To(BeNil())
			})
			It("Should return success & delete the scan pods (doDelete=true)", func() {
				result, err := reconciler.phaseDoneHandler(handler, compliancescaninstance, logger, doDelete)
				Expect(err).To(BeNil())
				Expect(result).ToNot(BeNil())

				var pods corev1.PodList
				err = reconciler.Client.List(context.TODO(), &pods)
				Expect(err).To(BeNil())
				Expect(pods.Items).To(BeEmpty())

				var secrets corev1.SecretList
				err = reconciler.Client.List(context.TODO(), &secrets)
				Expect(err).To(BeNil())
				Expect(secrets.Items).To(BeEmpty())
			})
		})
	})
})
