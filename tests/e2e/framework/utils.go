package framework

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/compliance-operator/pkg/utils"
	imagev1 "github.com/openshift/api/image/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (f *Framework) AssertMustHaveParsedProfiles(pbName, productType, productName string) error {
	var l compv1alpha1.ProfileList
	o := &client.ListOptions{
		LabelSelector: labels.SelectorFromSet(map[string]string{
			compv1alpha1.ProfileBundleOwnerLabel: pbName,
		}),
	}
	if err := f.Client.List(context.TODO(), &l, o); err != nil {
		return err
	}
	if len(l.Items) <= 0 {
		return fmt.Errorf("failed to get profiles from ProfileBundle %s. Expected at least one but got %d", pbName, len(l.Items))
	}

	for _, p := range l.Items {
		if p.Annotations[compv1alpha1.ProductTypeAnnotation] != productType {
			return fmt.Errorf("expected %s to be %s, got %s instead", compv1alpha1.ProductTypeAnnotation, productType, p.Annotations[compv1alpha1.ProductTypeAnnotation])
		}

		if p.Annotations[compv1alpha1.ProductAnnotation] != productName {
			return fmt.Errorf("expected %s to be %s, got %s instead", compv1alpha1.ProductAnnotation, productName, p.Annotations[compv1alpha1.ProductAnnotation])
		}
	}
	return nil
}

// AssertScanHasTotalCheckCounts asserts that the scan has the expected total check counts
func (f *Framework) AssertScanHasTotalCheckCounts(namespace, scanName string) error {
	// check if scan has annotation
	var scan compv1alpha1.ComplianceScan
	key := types.NamespacedName{Namespace: namespace, Name: scanName}
	if err := f.Client.Get(context.Background(), key, &scan); err != nil {
		return err
	}
	if scan.Annotations == nil {
		return fmt.Errorf("expected annotations to be not nil")
	}
	if scan.Annotations[compv1alpha1.ComplianceCheckCountAnnotation] == "" {
		return fmt.Errorf("expected %s to be not empty", compv1alpha1.ComplianceCheckCountAnnotation)
	}

	gotCheckCount, err := strconv.Atoi(scan.Annotations[compv1alpha1.ComplianceCheckCountAnnotation])
	if err != nil {
		return fmt.Errorf("failed to convert %s to int: %w", compv1alpha1.ComplianceCheckCountAnnotation, err)
	}

	var checkList compv1alpha1.ComplianceCheckResultList
	checkListOpts := client.MatchingLabels{
		compv1alpha1.ComplianceScanLabel: scanName,
	}
	if err := f.Client.List(context.TODO(), &checkList, &checkListOpts); err != nil {
		return err
	}

	if gotCheckCount != len(checkList.Items) {
		return fmt.Errorf("expected %s to be %d, got %d instead", compv1alpha1.ComplianceCheckCountAnnotation, len(checkList.Items), gotCheckCount)
	}

	return nil
}

// AssertRuleCheckTypeChangedAnnotationKey asserts that the rule check type changed annotation key exists
func (f *Framework) AssertRuleCheckTypeChangedAnnotationKey(namespace, ruleName, lastCheckType string) error {
	var r compv1alpha1.Rule
	key := types.NamespacedName{Namespace: namespace, Name: ruleName}
	if err := f.Client.Get(context.Background(), key, &r); err != nil {
		return err
	}
	if r.Annotations == nil {
		return fmt.Errorf("expected annotations to be not nil")
	}
	if r.Annotations[compv1alpha1.RuleLastCheckTypeChangedAnnotationKey] != lastCheckType {
		return fmt.Errorf("expected %s to be %s, got %s instead", compv1alpha1.RuleLastCheckTypeChangedAnnotationKey, lastCheckType, r.Annotations[compv1alpha1.RuleLastCheckTypeChangedAnnotationKey])
	}
	return nil
}

func (f *Framework) DoesRuleExist(namespace, ruleName string) (error, bool) {
	err, found := f.DoesObjectExist("Rule", namespace, ruleName)
	if err != nil {
		return fmt.Errorf("failed to get rule %s", ruleName), found
	}
	return err, found
}

func (f *Framework) DoesObjectExist(kind, namespace, name string) (error, bool) {
	obj := unstructured.Unstructured{}
	obj.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   compv1alpha1.SchemeGroupVersion.Group,
		Version: compv1alpha1.SchemeGroupVersion.Version,
		Kind:    kind,
	})

	key := types.NamespacedName{Namespace: namespace, Name: name}
	err := f.Client.Get(context.TODO(), key, &obj)
	if apierrors.IsNotFound(err) {
		return nil, false
	} else if err == nil {
		return nil, true
	}

	return err, false
}

func IsRuleInProfile(ruleName string, profile *compv1alpha1.Profile) bool {
	for _, ref := range profile.Rules {
		if string(ref) == ruleName {
			return true
		}
	}
	return false
}

func (f *Framework) AssertProfileBundleMustHaveParsedRules(pbName string) error {
	var r compv1alpha1.RuleList
	o := &client.ListOptions{
		LabelSelector: labels.SelectorFromSet(map[string]string{
			compv1alpha1.ProfileBundleOwnerLabel: pbName,
		}),
	}
	if err := f.Client.List(context.TODO(), &r, o); err != nil {
		return fmt.Errorf("failed to get rule list from ProfileBundle %s: %w", pbName, err)
	}
	if len(r.Items) <= 0 {
		return fmt.Errorf("rules were not parsed from the ProfileBundle %s. Expected more than one, got %d", pbName, len(r.Items))
	}
	return nil
}

func GetObjNameFromTest(t *testing.T) string {
	fullTestName := t.Name()
	regexForCapitals := regexp.MustCompile(`[A-Z]`)

	testNameInitIndex := strings.LastIndex(fullTestName, "/") + 1

	// Remove test prefix
	testName := fullTestName[testNameInitIndex:]

	// convert capitals to lower case letters with hyphens prepended
	hyphenedTestName := regexForCapitals.ReplaceAllStringFunc(
		testName,
		func(currentMatch string) string {
			return "-" + strings.ToLower(currentMatch)
		})
	// remove double hyphens
	testNameNoDoubleHyphens := strings.ReplaceAll(hyphenedTestName, "--", "-")
	// Remove leading and trailing hyphens
	return strings.Trim(testNameNoDoubleHyphens, "-")
}

func ProcessErrorOrTimeout(err, timeoutErr error, message string) error {
	// Error in function call
	if err != nil {
		return fmt.Errorf("got error when %s: %w", message, err)
	}
	// Timeout
	if timeoutErr != nil {
		return fmt.Errorf("timed out when %s: %w", message, timeoutErr)
	}
	return nil
}

func (f *Framework) UpdateImageStreamTag(iSName, imagePath, namespace string) error {
	s := &imagev1.ImageStream{}
	key := types.NamespacedName{Name: iSName, Namespace: namespace}
	if err := f.Client.Get(context.TODO(), key, s); err != nil {
		return err
	}
	c := s.DeepCopy()
	// Updated tracked image reference
	c.Spec.Tags[0].From.Name = imagePath
	return f.Client.Update(context.TODO(), c)
}

func (f *Framework) GetImageStreamUpdatedDigest(iSName, namespace string) (string, error) {
	stream := &imagev1.ImageStream{}
	tagItemNum := 0
	key := types.NamespacedName{Name: iSName, Namespace: namespace}
	for tagItemNum < 2 {
		if err := f.Client.Get(context.TODO(), key, stream); err != nil {
			return "", err
		}
		tagItemNum = len(stream.Status.Tags[0].Items)
		time.Sleep(2 * time.Second)
	}

	// Last tag item is at index 0
	imgDigest := stream.Status.Tags[0].Items[0].Image
	return imgDigest, nil
}

func (f *Framework) WaitForDeploymentContentUpdate(pbName, imgDigest string) error {
	lo := &client.ListOptions{
		LabelSelector: labels.SelectorFromSet(map[string]string{
			"profile-bundle": pbName,
			"workload":       "profileparser",
		}),
	}

	var depls appsv1.DeploymentList
	var lastErr error
	timeouterr := wait.Poll(RetryInterval, Timeout, func() (bool, error) {
		lastErr = f.Client.List(context.TODO(), &depls, lo)
		if lastErr != nil {
			log.Printf("failed getting deployment list: %s... retrying\n", lastErr)
			return false, nil
		}
		depl := depls.Items[0]
		currentImg := depl.Spec.Template.Spec.InitContainers[0].Image
		// The image will have a different path, but the digest should be the same
		if !strings.HasSuffix(currentImg, imgDigest) {
			log.Println("content image isn't up-to-date... retrying")
			return false, nil
		}
		return true, nil
	})
	// Error in function call
	if lastErr != nil {
		return lastErr
	}
	// Timeout
	if timeouterr != nil {
		return timeouterr
	}

	log.Printf("profile parser deployment updated\n")

	var pods corev1.PodList
	timeouterr = wait.Poll(RetryInterval, Timeout, func() (bool, error) {
		lastErr = f.Client.List(context.TODO(), &pods, lo)
		if lastErr != nil {
			log.Printf("failed to list pods: %s... retrying", lastErr)
			return false, nil
		}

		// Deployment updates will trigger a rolling update, so we might have
		// more than one pod. We only care about the newest
		pod := utils.FindNewestPod(pods.Items)

		currentImg := pod.Spec.InitContainers[0].Image
		if !strings.HasSuffix(currentImg, imgDigest) {
			log.Println("content image isn't up-to-date... retrying")
			return false, nil
		}
		if len(pod.Status.InitContainerStatuses) != 2 {
			log.Println("content parsing in progress... retrying")
			return false, nil
		}

		// The profileparser will take time, so we know it'll be index 1
		ppStatus := pod.Status.InitContainerStatuses[1]
		if !ppStatus.Ready {
			log.Println("container not ready... retrying")
			return false, nil
		}
		return true, nil
	})
	// Error in function call
	if lastErr != nil {
		return lastErr
	}
	// Timeout
	if timeouterr != nil {
		return timeouterr
	}
	log.Println("profile parser deployment done")
	return nil
}

func (f *Framework) CreateImageStream(iSName, namespace, imgPath string) (*imagev1.ImageStream, error) {
	stream := &imagev1.ImageStream{
		TypeMeta:   metav1.TypeMeta{APIVersion: imagev1.SchemeGroupVersion.String(), Kind: "ImageStream"},
		ObjectMeta: metav1.ObjectMeta{Name: iSName, Namespace: namespace},
		Spec: imagev1.ImageStreamSpec{
			Tags: []imagev1.TagReference{
				{
					Name: "latest",
					From: &corev1.ObjectReference{
						Kind: "DockerImage",
						Name: imgPath,
					},
					ReferencePolicy: imagev1.TagReferencePolicy{
						Type: imagev1.LocalTagReferencePolicy,
					},
				},
			},
		},
	}
	err := f.Client.Create(context.TODO(), stream, nil)
	return stream, err
}

func writeToArtifactsDir(dir, scan, pod, container, log string) error {
	logPath := path.Join(dir, fmt.Sprintf("%s_%s_%s.log", scan, pod, container))
	logFile, err := os.Create(logPath)
	if err != nil {
		return err
	}
	// #nosec G307
	defer logFile.Close()
	_, err = io.WriteString(logFile, log)
	if err != nil {
		return err
	}
	return nil
}

func AssertEachMetric(namespace string, expectedMetrics map[string]int) error {
	metricErrs := make([]error, 0)
	metricsOutput, err := getMetricResults(namespace)
	if err != nil {
		return err
	}
	for metric, i := range expectedMetrics {
		err := assertMetric(metricsOutput, metric, i)
		if err != nil {
			metricErrs = append(metricErrs, err)
		}
	}
	if len(metricErrs) > 0 {
		for err := range metricErrs {
			log.Println(err)
		}
		return errors.New("unexpected metrics value")
	}
	return nil
}

func (f *Framework) AssertMetricsEndpointUsesHTTPVersion(endpoint, version string) error {
	ocPath, err := exec.LookPath("oc")
	if err != nil {
		return err
	}

	curlCMD := "curl -i -ks -H \"Authorization: Bearer `cat /var/run/secrets/kubernetes.io/serviceaccount/token`\" " + endpoint
	// We're just under test.
	// G204 (CWE-78): Subprocess launched with variable (Confidence: HIGH, Severity: MEDIUM)
	// #nosec
	cmd := exec.Command(ocPath,
		"run", "--rm", "-i", "--restart=Never", "--image=registry.fedoraproject.org/fedora-minimal:latest",
		"-n", f.OperatorNamespace, "metrics-test", "--", "bash", "-c", curlCMD,
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error getting output %s", err)
	}
	if !strings.Contains(string(out), version) {
		return fmt.Errorf("metric endpoint is not using %s", version)
	}
	return nil
}

func assertMetric(content, metric string, expected int) error {
	val, err := parseMetric(content, metric)
	if err != nil {
		return err
	}
	if val != expected {
		return fmt.Errorf("expected %v for counter %s, got %v", expected, metric, val)
	}
	return nil
}

// parseMetrics checks the contents for the number of metrics as a substring
// and returns the number of occurrences along with any errors.
func parseMetric(content, metric string) (int, error) {
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, metric) {
			fields := strings.Fields(line)
			if len(fields) != 2 {
				return 0, fmt.Errorf("invalid metric")
			}
			i, err := strconv.Atoi(fields[1])
			if err != nil {
				return 0, fmt.Errorf("invalid metric value")
			}
			return i, nil
		}
	}
	return 0, nil
}

func getMetricResults(namespace string) (string, error) {
	ocPath, err := exec.LookPath("oc")
	if err != nil {
		return "", err
	}
	// We're just under test.
	// G204 (CWE-78): Subprocess launched with variable (Confidence: HIGH, Severity: MEDIUM)
	// #nosec
	cmd := exec.Command(ocPath,
		"run", "--rm", "-i", "--restart=Never", "--image=registry.fedoraproject.org/fedora-minimal:latest",
		"-n", namespace, "metrics-test", "--", "bash", "-c",
		getTestMetricsCMD(namespace),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("error getting output %s", err)
	}
	log.Printf("metrics output:\n%s\n", string(out))
	return string(out), nil
}

func getTestMetricsCMD(namespace string) string {
	var curlCMD = "curl -ks -H \"Authorization: Bearer `cat /var/run/secrets/kubernetes.io/serviceaccount/token`\" "
	return curlCMD + fmt.Sprintf("https://metrics.%s.svc:8585/metrics-co", namespace)
}

func GetPoolNodeRoleSelector() map[string]string {
	return utils.GetNodeRoleSelector(TestPoolName)
}
