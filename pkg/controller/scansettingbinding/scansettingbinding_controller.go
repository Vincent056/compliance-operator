package scansettingbinding

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/ComplianceAsCode/compliance-operator/pkg/controller/metrics"

	"github.com/ComplianceAsCode/compliance-operator/pkg/controller/common"
	"github.com/ComplianceAsCode/compliance-operator/pkg/utils"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	compliancev1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
)

const (
	// The default time we should wait before requeuing
	requeueAfterDefault = 10 * time.Second
	// roleValRegexp evaluates role values. The limit comes
	// from the label limit (63) minus the length of
	// "node-role.kubernetes.io/".
	roleValRegexp     = `^([a-zA-Z0-9-]){1,39}$`
	invalidRoleRegexp = `[^a-zA-Z0-9-]+`
)

var log = logf.Log.WithName("scansettingbindingctrl")

func (r *ReconcileScanSettingBinding) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&compliancev1alpha1.ScanSettingBinding{}).
		Complete(r)
}

func Add(mgr manager.Manager, met *metrics.Metrics, _ utils.CtlplaneSchedulingInfo, _ *kubernetes.Clientset) error {
	return add(mgr, newReconciler(mgr, met))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, met *metrics.Metrics) reconcile.Reconciler {
	return &ReconcileScanSettingBinding{Client: mgr.GetClient(), Scheme: mgr.GetScheme(),
		Recorder:    common.NewSafeRecorder("scansettingbindingctrl", mgr),
		Metrics:     met,
		roleVal:     regexp.MustCompile(roleValRegexp),
		invalidRole: regexp.MustCompile(invalidRoleRegexp),
	}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("scansettingbinding-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to primary resource ScanSettingBinding
	err = c.Watch(&source.Kind{Type: &compliancev1alpha1.ScanSettingBinding{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	// Watch for changes to secondary resource ScanSetting. Since Setting does not link directly to a Binding,
	// but the other way around, we use a mapper to enqueue requests for Binding(s) used by a Setting
	ssMapper := &scanSettingMapper{mgr.GetClient()}
	err = c.Watch(&source.Kind{Type: &compliancev1alpha1.ScanSetting{}}, handler.EnqueueRequestsFromMapFunc(ssMapper.Map))
	if err != nil {
		return err
	}

	// Watch for changes to secondary resource TailoredProfile. Since TailoredProfile does not link directly to a Binding,
	// but the other way around, we use a mapper to enqueue requests for TailoredProfiles(s) used by a Setting
	tpMapper := &tailoredProfileMapper{mgr.GetClient()}
	err = c.Watch(&source.Kind{Type: &compliancev1alpha1.TailoredProfile{}}, handler.EnqueueRequestsFromMapFunc(tpMapper.Map))
	if err != nil {
		return err
	}

	// Watch for changes to secondary resource ComplianceScans and requeue the owner ComplianceSuite
	err = c.Watch(&source.Kind{Type: &compliancev1alpha1.ComplianceSuite{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &compliancev1alpha1.ScanSettingBinding{},
	})
	if err != nil {
		return err
	}

	return nil
}

// blank assignment to verify that ReconcileScanSettingBinding implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileScanSettingBinding{}

// ReconcileScanSettingBinding reconciles a ScanSettingBinding object
type ReconcileScanSettingBinding struct {
	Client      client.Client
	Scheme      *runtime.Scheme
	Recorder    *common.SafeRecorder
	Metrics     *metrics.Metrics
	roleVal     *regexp.Regexp
	invalidRole *regexp.Regexp
}

// FIXME: generalize for other controllers?
func (r *ReconcileScanSettingBinding) Eventf(object runtime.Object, eventtype, reason, messageFmt string, args ...interface{}) {
	if r.Recorder == nil {
		return
	}

	r.Recorder.Eventf(object, eventtype, reason, messageFmt, args...)
}

func (r *ReconcileScanSettingBinding) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling ScanSettingBinding")

	// Fetch the ScanSettingBinding instance
	instance := &compliancev1alpha1.ScanSettingBinding{}
	err := r.Client.Get(context.TODO(), request.NamespacedName, instance)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			return reconcile.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return reconcile.Result{}, err
	}

	// We should always have a condition here
	if instance.Status.Conditions.GetCondition("Ready") == nil {
		ssb := instance.DeepCopy()
		ssb.Status.SetConditionPending()
		err := r.Client.Status().Update(context.TODO(), ssb)
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("Couldn't update ScanSettingBinding status: %s", err)
		}
		// this was a fatal error, don't requeue
		return reconcile.Result{}, nil
	}

	suite := compliancev1alpha1.ComplianceSuite{
		ObjectMeta: metav1.ObjectMeta{
			Name:      instance.Name,
			Namespace: instance.Namespace,
		},
		Spec: compliancev1alpha1.ComplianceSuiteSpec{},
	}

	// Set SettingBinding as the owner of the Suite
	if err := controllerutil.SetControllerReference(instance, &suite, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}

	var nodeProduct string
	for i := range instance.Profiles {
		ss := &instance.Profiles[i]

		key := types.NamespacedName{Namespace: instance.Namespace, Name: ss.Name}
		profileObj, geterr := getUnstructured(r, instance, key, ss.Kind, ss.APIGroup, reqLogger)
		if geterr != nil {
			return reconcile.Result{}, geterr
		}

		if profileObj.GetKind() == "TailoredProfile" {
			val, found, nsErr := unstructured.NestedString(
				profileObj.Object, "status", "state")
			if nsErr != nil {
				reqLogger.Error(nsErr, "Fetching state of tailored profile",
					"TailoredProfile", profileObj.GetName())
			}
			if !found {
				reqLogger.Info("Requeuing as TailoredProfile hasn't been processed",
					"TailoredProfile", profileObj.GetName())
				return reconcile.Result{Requeue: true, RequeueAfter: requeueAfterDefault}, nil
			}
			if val == string(compliancev1alpha1.TailoredProfileStateError) {
				msg := "The TailoredProfile referenced has an error and is not usable"
				ssb := instance.DeepCopy()
				ssb.Status.SetConditionInvalid(msg)
				if updateErr := r.Client.Status().Update(context.TODO(), ssb); updateErr != nil {
					return reconcile.Result{}, fmt.Errorf("couldn't update ScanSettingBinding condition: %w", updateErr)
				}
				return reconcile.Result{}, nil
			}
			if val != string(compliancev1alpha1.TailoredProfileStateReady) {
				reqLogger.Info("Requeuing as TailoredProfile isn't yet ready",
					"TailoredProfile", profileObj.GetName())
				return reconcile.Result{Requeue: true, RequeueAfter: requeueAfterDefault}, nil
			}
		}

		scan, product, err := newCompScanFromBindingProfile(r, instance, profileObj, log)
		if err != nil {
			return common.ReturnWithRetriableError(reqLogger, err)
		}

		nodeProduct = getRelevantProduct(nodeProduct, product)

		if isDifferentProduct(nodeProduct, product) {
			msg := fmt.Sprintf("ScanSettingBinding defines multiple products: %s and %s", product, nodeProduct)
			r.Eventf(instance, corev1.EventTypeWarning, "MultipleProducts", msg)

			ssb := instance.DeepCopy()
			ssb.Status.SetConditionInvalid(msg)
			if updateErr := r.Client.Status().Update(context.TODO(), ssb); updateErr != nil {
				return reconcile.Result{}, fmt.Errorf("couldn't update ScanSettingBinding condition: %w", updateErr)
			}
			// Don't requeue in this case, nothing we can do
			return reconcile.Result{}, nil
		}

		suite.Spec.Scans = append(suite.Spec.Scans, *scan)
	}

	if instance.SettingsRef != nil {
		err := r.applyConstraint(instance, &suite, instance.SettingsRef, log)
		if err != nil {
			return common.ReturnWithRetriableError(reqLogger, err)
		}
	}

	found := compliancev1alpha1.ComplianceSuite{}
	err = r.Client.Get(context.TODO(), types.NamespacedName{Namespace: suite.Namespace, Name: suite.Name}, &found)
	if errors.IsNotFound(err) {
		err = r.Client.Create(context.TODO(), &suite)
		if err == nil {
			reqLogger.Info("Suite created", "suite.Name", suite.Name)
			r.Eventf(
				instance, corev1.EventTypeNormal, "SuiteCreated",
				"ComplianceSuite %s/%s created", suite.Namespace, suite.Name,
			)

			ssb := instance.DeepCopy()
			ssb.Status.SetConditionReady()
			ssb.Status.OutputRef = &corev1.TypedLocalObjectReference{
				APIGroup: &compliancev1alpha1.SchemeGroupVersion.Group,
				Kind:     "ComplianceSuite",
				Name:     suite.GetName(),
			}
			if updateErr := r.Client.Status().Update(context.TODO(), ssb); updateErr != nil {
				return reconcile.Result{}, fmt.Errorf("couldn't update ScanSettingBinding condition: %w", updateErr)
			}
			return reconcile.Result{}, nil
		}

		reqLogger.Error(err, "Suite failed to create", "suite.Name", suite.Name)
		r.Eventf(
			instance, corev1.EventTypeWarning, "SuiteNotCreated",
			"ComplianceSuite %s/%s could not be created: %s", suite.Namespace, suite.Name, err,
		)
		return reconcile.Result{}, err
	} else if err != nil {
		return reconcile.Result{}, nil
	}

	// The suite already exists, should we update?
	if suiteNeedsUpdate(&suite, &found) {
		found.Spec = suite.Spec
		err = r.Client.Update(context.TODO(), &found)
		if err == nil {
			reqLogger.Info("Suite updated", "suite.Name", suite.Name)
			r.Eventf(
				instance, corev1.EventTypeNormal, "SuiteUpdated",
				"ComplianceSuite %s/%s updatd", suite.Namespace, suite.Name,
			)
		} else {
			reqLogger.Error(err, "Suite failed to update", "suite.Name", suite.Name)
			r.Eventf(
				instance, corev1.EventTypeWarning, "SuiteNotUpdated",
				"ComplianceSuite %s/%s could not be updated: %s", suite.Namespace, suite.Name, err,
			)
		}
		return reconcile.Result{}, err
	}

	if scanSettingBindingStatusNeedsUpdate(instance) {
		ssb := instance.DeepCopy()
		ssb.Status.SetConditionReady()
		group := found.GroupVersionKind().Group
		ssb.Status.OutputRef = &corev1.TypedLocalObjectReference{
			APIGroup: &group,
			Kind:     found.GroupVersionKind().Kind,
			Name:     found.GetName(),
		}
		if updateErr := r.Client.Status().Update(context.TODO(), ssb); updateErr != nil {
			return reconcile.Result{}, fmt.Errorf("couldn't update ScanSettingBinding condition: %w", updateErr)
		}
	} else {
		reqLogger.Info("Suite does not need update", "suite.Name", suite.Name)
	}

	if found.Status.Phase == compliancev1alpha1.PhaseDone {
		reqLogger.Info("Generating events for scansettingbinding")
		common.GenerateEventForResult(r.Recorder, instance, instance, found.Status.Result)
	}

	return reconcile.Result{}, nil
}

func getRelevantProduct(nodeProduct, incomingProduct string) string {
	// Initialize
	if nodeProduct == "" && incomingProduct != "" {
		return incomingProduct
	}
	return nodeProduct
}

func isDifferentProduct(nodeProduct, incomingProduct string) bool {
	return incomingProduct != "" && incomingProduct != nodeProduct
}

func (r *ReconcileScanSettingBinding) applyConstraint(
	instance *compliancev1alpha1.ScanSettingBinding,
	suite *compliancev1alpha1.ComplianceSuite,
	constraintRef *compliancev1alpha1.NamedObjectReference,
	logger logr.Logger,
) error {
	key := types.NamespacedName{Namespace: instance.Namespace, Name: constraintRef.Name}
	constraint, err := getUnstructured(r, instance, key, constraintRef.Kind, constraintRef.APIGroup, logger)
	if err != nil {
		return err
	}

	if err := isCmpv1Alpha1Gvk(constraint, "ScanSetting"); err != nil {
		return err
	}
	v1setting := compliancev1alpha1.ScanSetting{}

	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(constraint.Object, &v1setting); err != nil {
		return common.WrapNonRetriableCtrlError(err)
	}

	if valErr := r.validateRoles(instance, &v1setting, logger); valErr != nil {
		return common.NewRetriableCtrlErrorWithCustomHandler(
			func() (reconcile.Result, error) {
				return reconcile.Result{}, nil
			}, "error validating ScanSetting '%s' roles: %w", v1setting.GetName(), valErr)
	}

	// create per-role scans
	suite.Spec.Scans = r.createScansWithSelector(suite, &v1setting, logger)
	// apply settings for suite - deep copy to future proof in case there are any slices or so later
	suite.Spec.ComplianceSuiteSettings = *v1setting.ComplianceSuiteSettings.DeepCopy()
	// apply settings for scans, need to DeepCopy as ScanSetting contains a slice
	for i := range suite.Spec.Scans {
		scan := &suite.Spec.Scans[i]
		scan.ComplianceScanSettings = *v1setting.ComplianceScanSettings.DeepCopy()
	}

	return nil
}

func (r *ReconcileScanSettingBinding) validateRoles(
	binding *compliancev1alpha1.ScanSettingBinding,
	setting *compliancev1alpha1.ScanSetting,
	logger logr.Logger,
) error {
	if len(setting.Roles) == 0 {
		r.Eventf(setting, corev1.EventTypeWarning, "EmptyRoles",
			"The ScanSetting's roles are empty. Node scans won't be scheduled.")
		return nil
	}
	// This is fine and expected
	if len(setting.Roles) == 1 && setting.Roles[0] == compliancev1alpha1.AllRoles {
		return nil
	}
	for _, role := range setting.Roles {
		if role == compliancev1alpha1.AllRoles {
			return fmt.Errorf("role %s cannot be used alongside other roles", compliancev1alpha1.AllRoles)
		}
		if !r.roleVal.MatchString(role) {
			return fmt.Errorf("role %s is invalid", role)
		}
		if !isBuiltInRole(role) {
			// if the scan setting is not using a built-in role, we need to make sure that the role is set
			// in a tailored profile
			if err := r.verifyRoleInScanSettingBinding(binding, role, logger); err != nil {
				msg := "The scanSetting references a non-default role, but either no tailored profile is set or the role variables are not set"
				ssb := binding.DeepCopy()
				ssb.Status.SetConditionInvalid(msg)
				if updateErr := r.Client.Status().Update(context.TODO(), ssb); updateErr != nil {
					return fmt.Errorf("couldn't update ScanSettingBinding condition: %w", updateErr)
				}
				return fmt.Errorf("role %s is not set in any tailored profile: %w", role, err)
			}
		}
	}
	return nil
}

// return an error if the ssb references at least one Platform profile that is not
// tailored or a tailored profile that does not have the role set
func (r *ReconcileScanSettingBinding) verifyRoleInScanSettingBinding(
	binding *compliancev1alpha1.ScanSettingBinding,
	role string,
	logger logr.Logger,
) error {
	profilesToCheck := []compliancev1alpha1.NamedObjectReference{}

	for i := range binding.Profiles {
		prfRef := &binding.Profiles[i]

		key := types.NamespacedName{Namespace: binding.Namespace, Name: prfRef.Name}
		prfObj, err := getUnstructured(r, binding, key, prfRef.Kind, prfRef.APIGroup, logger)
		if err != nil {
			return fmt.Errorf("error getting Profile %s: %w", prfRef.Name, err)
		}

		profileType, err := getTpScanType(r, binding, prfRef.APIGroup, prfObj, logger)
		if err != nil {
			logger.Info("error getting scan type, assuming Platform", "profile", prfRef.Name, "error", err)
			profileType = compliancev1alpha1.ScanTypePlatform
		}

		if profileType == compliancev1alpha1.ScanTypeNode {
			continue
		}

		profilesToCheck = append(profilesToCheck, *prfRef)
	}

	if len(profilesToCheck) == 0 {
		// all profiles we had were node profiles, so we don't need to check for the roles
		return nil
	}

	// at least one of profilesToCheck must be a TP with the role set
	for i := range profilesToCheck {
		prfRef := &profilesToCheck[i]

		if prfRef.Kind != "TailoredProfile" {
			// we only care about tailored profiles
			continue
		}

		key := types.NamespacedName{Namespace: binding.Namespace, Name: prfRef.Name}
		tp, geterr := getUnstructured(r, binding, key, prfRef.Kind, prfRef.APIGroup, logger)
		if geterr != nil {
			return fmt.Errorf("error getting TailoredProfile %s: %w", prfRef.Name, geterr)
		}

		if err := isCmpv1Alpha1Gvk(tp, "TailoredProfile"); err != nil {
			return common.WrapNonRetriableCtrlError(err)
		}

		v1alphaTp := compliancev1alpha1.TailoredProfile{}
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(tp.Object, &v1alphaTp); err != nil {
			return common.WrapNonRetriableCtrlError(err)
		}

		for vi := range v1alphaTp.Spec.SetValues {
			val := &v1alphaTp.Spec.SetValues[vi]
			if val.Value == role {
				return nil
			}
		}
	}

	msg := fmt.Sprintf("role %s is not set in any variable in tailored profiles", role)
	r.Eventf(binding, corev1.EventTypeWarning, "", msg)
	return fmt.Errorf(msg)
}

func (r *ReconcileScanSettingBinding) createScansWithSelector(
	suite *compliancev1alpha1.ComplianceSuite,
	v1setting *compliancev1alpha1.ScanSetting,
	logger logr.Logger,
) []compliancev1alpha1.ComplianceScanSpecWrapper {
	scansWithSelector := make([]compliancev1alpha1.ComplianceScanSpecWrapper, 0)
	for _, scan := range suite.Spec.Scans {
		logger.Info("Processing original scan", "scan.Name", scan.Name)
		if strings.ToLower(string(scan.ScanType)) == "node" {
			for _, role := range v1setting.Roles {
				scanCopy := scan.DeepCopy()
				scanCopy.Name = scan.Name + "-" + r.sanitizeRoleForName(role)
				scanCopy.NodeSelector = utils.GetNodeRoleSelector(role)
				logger.Info("Adding per-role scan", "scanCopy.Name", scanCopy.Name)
				scansWithSelector = append(scansWithSelector, *scanCopy)
			}
		} else {
			scanCopy := scan.DeepCopy()
			logger.Info("Adding platform scan", "scanCopy.Name", scanCopy.Name)
			scansWithSelector = append(scansWithSelector, *scanCopy)
		}

	}

	return scansWithSelector
}

// returns a sanitized role name that can be used
// for a name. Note that it is also assumed that validation
// has already taken place.
func (r *ReconcileScanSettingBinding) sanitizeRoleForName(roleName string) string {
	if roleName == compliancev1alpha1.AllRoles {
		return "a-all"
	}
	// Remove all invalid characters if anything slips through
	// here. This should be a no-op since validation
	// has already happened.
	return r.invalidRole.ReplaceAllString(roleName, "")

}

func isBuiltInRole(role string) bool {
	return role == "master" || role == "worker" || role == "control-plane"
}

func newCompScanFromBindingProfile(r *ReconcileScanSettingBinding, instance *compliancev1alpha1.ScanSettingBinding, profile *unstructured.Unstructured, logger logr.Logger) (*compliancev1alpha1.ComplianceScanSpecWrapper, string, error) {
	parsedProfReference, err := resolveProfileReference(r, instance, profile, logger)
	if err != nil {
		return nil, "", err
	}

	scan, platform, err := profileReferenceToScan(parsedProfReference)
	if err != nil {
		r.Eventf(
			instance, corev1.EventTypeWarning, "ScanCreateError",
			"Cannot create scan: %v", err,
		)
		return nil, "", err
	}

	return scan, platform, nil
}

type profileReference struct {
	name string

	tailoredProfile *unstructured.Unstructured
	profile         *unstructured.Unstructured
	profileBundle   *unstructured.Unstructured
}

func profileReferenceToScan(reference *profileReference) (*compliancev1alpha1.ComplianceScanSpecWrapper, string, error) {
	var err error

	scan := compliancev1alpha1.ComplianceScanSpecWrapper{
		ComplianceScanSpec: compliancev1alpha1.ComplianceScanSpec{},
		Name:               reference.name,
	}

	err = fillContentData(reference.profileBundle, &scan)
	if err != nil {
		return nil, "", err
	}

	if reference.tailoredProfile != nil {
		err = fillTailoredProfileData(reference.tailoredProfile, &scan)
		if err != nil {
			return nil, "", err
		}
	} else if reference.profile != nil {
		err = fillProfileData(reference.profile, &scan)
		if err != nil {
			return nil, "", err
		}
	} else {
		return nil, "", fmt.Errorf("neither profile nor tailoredProfile are known")
	}

	var product string
	if reference.profile != nil {
		err = setScanType(&scan, reference.profile.GetAnnotations())
		if err != nil {
			return nil, "", fmt.Errorf("cannot infer scan type from %s: %v", reference.profile.GetName(), err)
		}

		if scan.ScanType == compliancev1alpha1.ScanTypeNode {
			product = reference.profile.GetAnnotations()[compliancev1alpha1.ProductAnnotation]
		}
	} else if reference.tailoredProfile != nil {
		err = setScanType(&scan, reference.tailoredProfile.GetAnnotations())
		if err != nil {
			return nil, "", fmt.Errorf("cannot infer scan type from %s: %v", reference.tailoredProfile.GetName(), err)
		}
	}

	return &scan, product, nil
}

func fillContentData(bundle *unstructured.Unstructured, scan *compliancev1alpha1.ComplianceScanSpecWrapper) error {
	if err := isCmpv1Alpha1Gvk(bundle, "ProfileBundle"); err != nil {
		return common.WrapNonRetriableCtrlError(err)
	}

	v1alphaBundle := compliancev1alpha1.ProfileBundle{}
	err := runtime.DefaultUnstructuredConverter.FromUnstructured(bundle.Object, &v1alphaBundle)
	if err != nil {
		return common.WrapNonRetriableCtrlError(err)
	}

	// make sure the bundle is not yet being processed, especially when we support updates
	if v1alphaBundle.Status.DataStreamStatus != compliancev1alpha1.DataStreamValid {
		return common.NewRetriableCtrlErrorWithCustomHandler(func() (reconcile.Result, error) {
			return reconcile.Result{RequeueAfter: requeueAfterDefault, Requeue: true}, nil
		}, "ProfileBundle '%s' is still being processed", v1alphaBundle.GetName())
	}

	scan.Content = v1alphaBundle.Spec.ContentFile
	scan.ContentImage = v1alphaBundle.Spec.ContentImage
	return nil
}

func fillTailoredProfileData(tp *unstructured.Unstructured, scan *compliancev1alpha1.ComplianceScanSpecWrapper) error {
	if err := isCmpv1Alpha1Gvk(tp, "TailoredProfile"); err != nil {
		return common.WrapNonRetriableCtrlError(err)
	}

	v1alphaTp := compliancev1alpha1.TailoredProfile{}
	err := runtime.DefaultUnstructuredConverter.FromUnstructured(tp.Object, &v1alphaTp)
	if err != nil {
		return common.WrapNonRetriableCtrlError(err)
	}

	scan.Profile = v1alphaTp.Status.ID
	if v1alphaTp.Status.OutputRef.Name != "" {
		// FIXME: OutputRef also has a namespace, but tailorringCofnigMapRef not?
		scan.TailoringConfigMap = &compliancev1alpha1.TailoringConfigMapRef{Name: v1alphaTp.Status.OutputRef.Name}
	}

	return nil
}

func fillProfileData(p *unstructured.Unstructured, scan *compliancev1alpha1.ComplianceScanSpecWrapper) error {
	if err := isCmpv1Alpha1Gvk(p, "Profile"); err != nil {
		return common.WrapNonRetriableCtrlError(err)
	}

	v1alphaProfile := compliancev1alpha1.Profile{}
	err := runtime.DefaultUnstructuredConverter.FromUnstructured(p.Object, &v1alphaProfile)
	if err != nil {
		return common.WrapNonRetriableCtrlError(err)
	}

	scan.Profile = v1alphaProfile.ID

	return nil
}

func setScanType(scan *compliancev1alpha1.ComplianceScanSpecWrapper, annotations map[string]string) error {
	var err error

	scan.ComplianceScanSpec.ScanType, err = getScanType(annotations)
	return err
}

func getScanType(annotations map[string]string) (compliancev1alpha1.ComplianceScanType, error) {
	platformType, ok := annotations[compliancev1alpha1.ProductTypeAnnotation]
	if !ok {
		return compliancev1alpha1.ScanTypeNode, fmt.Errorf("no %s label found", compliancev1alpha1.ProductTypeAnnotation)
	}

	switch strings.ToLower(platformType) {
	case strings.ToLower(string(compliancev1alpha1.ScanTypeNode)):
		return compliancev1alpha1.ScanTypeNode, nil
	default:
		break
	}

	return compliancev1alpha1.ScanTypePlatform, nil
}

func getTpScanType(
	r *ReconcileScanSettingBinding,
	binding *compliancev1alpha1.ScanSettingBinding,
	apiGroup string,
	prfObj *unstructured.Unstructured,
	logger logr.Logger,
) (compliancev1alpha1.ComplianceScanType, error) {
	profileType, err := getScanType(prfObj.GetAnnotations())
	if err == nil {
		return profileType, nil
	} else if prfObj.GetKind() != "TailoredProfile" {
		// profiles are pretty much always annotated. If not, let's just assume it's a platform scan. If not,
		// the scan would just fail later..
		logger.Info("error getting profile scan type, assuming Platform", "profile", prfObj.GetName(), "error", err)
		return compliancev1alpha1.ScanTypePlatform, nil
	}

	logger.Info("TailoredProfile had no annotation, trying the parent profile", "tailoredProfile", prfObj.GetName())
	val, found, nsErr := unstructured.NestedString(prfObj.Object, "spec", "extends")
	if nsErr != nil {
		logger.Error(nsErr, "Fetching state of tailored profile",
			"TailoredProfile", prfObj.GetName())
		return compliancev1alpha1.ScanTypePlatform, nsErr
	} else if !found {
		// if there is no extends, then this is a custom-created profile. Custom profiles would indicate that they
		// are node profiles either by using the -node suffix or by being properly annotated. Otherwise, even
		// the plain scan profile would assume platform, so let's do the same here.
		logger.Info("No extends field found in tailored profile", "TailoredProfile", prfObj.GetName())
		return compliancev1alpha1.ScanTypePlatform, nil
	}

	key := types.NamespacedName{Namespace: prfObj.GetNamespace(), Name: val}
	extendsObj, err := getUnstructured(r, binding, key, "Profile", apiGroup, logger)
	if err != nil {
		return compliancev1alpha1.ScanTypePlatform, fmt.Errorf("error getting Profile %s: %w", val, err)
	}

	extendsType, err := getScanType(extendsObj.GetAnnotations())
	if err != nil {
		return extendsType, common.NewNonRetriableCtrlError("error getting scan type for profile %s: %w", extendsObj.GetName(), err)
	}

	logger.Info("Got scan type from parent profile", "tailoredProfile", prfObj.GetName(), "profile", extendsObj.GetName(), "type", extendsType)
	return extendsType, nil
}

func resolveProfileReference(r *ReconcileScanSettingBinding, instance *compliancev1alpha1.ScanSettingBinding, profile *unstructured.Unstructured, logger logr.Logger) (*profileReference, error) {
	var profReference profileReference
	var err error

	profReference.name = profile.GetName()

	if profile.GetKind() == "Profile" {
		profReference.profile = profile
		profReference.tailoredProfile = nil

		profReference.profileBundle, err = resolveTypedParent(r, instance, "ProfileBundle", profReference.profile, logger)
		if err != nil {
			return nil, err
		}
	} else if profile.GetKind() == "TailoredProfile" {
		logger.Info("Retrieved a TailoredProfile, must also retrieve a Profile it points to")
		profReference.tailoredProfile = profile

		if ownerReferenceWithKind(profile, "Profile") != nil {
			profReference.profile, err = resolveProfile(r, instance, &profReference, logger)
			if err != nil {
				return nil, err
			}

			profReference.profileBundle, err = resolveTypedParent(r, instance, "ProfileBundle", profReference.profile, logger)
			if err != nil {
				return nil, err
			}
		} else if ownerReferenceWithKind(profile, "ProfileBundle") != nil {
			profReference.profileBundle, err = resolveTypedParent(r, instance, "ProfileBundle", profReference.tailoredProfile, logger)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, common.NewNonRetriableCtrlError("TailoredProfile must be owned by a Profile or ProfileBundle")
		}
	} else {
		r.Recorder.Eventf(
			instance, corev1.EventTypeWarning, "ReferenceError",
			"unsupported Kind %s, use one of Profile, TailoredProfile", profile.GetKind(),
		)
		return nil, common.NewNonRetriableCtrlError("unsupported Kind %s, use one of Profile, TailoredProfile", profile.GetKind())
	}

	return &profReference, nil
}

func resolveProfile(r *ReconcileScanSettingBinding, instance *compliancev1alpha1.ScanSettingBinding, profReference *profileReference, logger logr.Logger) (*unstructured.Unstructured, error) {
	return resolveTypedParent(r, instance, "Profile", profReference.tailoredProfile, logger)
}

func resolveTypedParent(r *ReconcileScanSettingBinding, instance *compliancev1alpha1.ScanSettingBinding, expectedKind string, child *unstructured.Unstructured, logger logr.Logger) (*unstructured.Unstructured, error) {
	parentReference := ownerReferenceWithKind(child, expectedKind)
	if parentReference == nil {
		r.Recorder.Eventf(
			instance, corev1.EventTypeWarning, "BadReference",
			"Couldn't find a %s owning %s %s", expectedKind, child.GetKind(), child.GetName(),
		)
		return nil, common.NewNonRetriableCtrlError("couldn't find an owner for %s %s owner", child.GetKind(), child.GetName())
	}

	logger.Info("Retrieving parent object",
		"child.Kind", child.GetKind(), "child.Name", child.GetName(),
		"parent.Name", parentReference.Name, "parent.Kind", expectedKind)

	key := types.NamespacedName{Namespace: instance.Namespace, Name: parentReference.Name}
	parentObj, err := getUnstructured(r, instance, key, parentReference.Kind, parentReference.APIVersion, logger)
	if err != nil {
		return nil, err
	}

	if parentObj.GetKind() != expectedKind {
		return nil, common.NewNonRetriableCtrlError("expected a %s, got %s", expectedKind, parentObj.GetKind())
	}

	return parentObj, nil

}

func ownerReferenceWithKind(object metav1.Object, kind string) *metav1.OwnerReference {
	for _, ref := range object.GetOwnerReferences() {
		if ref.Kind == kind {
			return &ref
		}
	}

	return nil
}

func getUnstructured(r *ReconcileScanSettingBinding, instance *compliancev1alpha1.ScanSettingBinding, key types.NamespacedName, kind, apiGroup string, logger logr.Logger) (*unstructured.Unstructured, error) {
	logger.Info("Resolving object", "kind", kind, "api", apiGroup)

	o := unstructured.Unstructured{}
	o.SetAPIVersion(apiGroup)
	o.SetKind(kind)

	err := r.Client.Get(context.TODO(), key, &o)
	if errors.IsNotFound(err) {
		return nil, common.NewRetriableCtrlErrorWithCustomHandler(func() (reconcile.Result, error) {
			// This might be a temporary issue in the order the objects are being created
			r.Eventf(
				instance, corev1.EventTypeWarning, "NamedReferenceLookupError",
				"NamedObjectReference %s %s not found", kind, key,
			)

			return reconcile.Result{RequeueAfter: requeueAfterDefault, Requeue: true}, nil
		}, "NamedObjectReference %s not found", key)
	} else if err != nil {
		logger.Error(err, "error looking up NamedObjectReference", "kind", kind, "key", key)
		return nil, err
	}

	return &o, nil
}

func newCmpv1Alpha1Gvk(kind string) schema.GroupVersionKind {
	return schema.GroupVersionKind{
		Group:   compliancev1alpha1.SchemeGroupVersion.Group,
		Version: compliancev1alpha1.SchemeGroupVersion.Version,
		Kind:    kind,
	}
}

// TODO: if we even support multiple versions, add an array of gvk:handler_fn tuples
func isCmpv1Alpha1Gvk(obj *unstructured.Unstructured, kind string) error {
	expGvk := newCmpv1Alpha1Gvk(kind)
	return isGvk(obj, &expGvk)
}

func isGvk(obj *unstructured.Unstructured, expectGvk *schema.GroupVersionKind) error {
	if obj == nil {
		return fmt.Errorf("nil object to check")
	}

	objGvk := obj.GetObjectKind().GroupVersionKind()

	if objGvk.Kind != expectGvk.Kind {
		return fmt.Errorf("expected Kind %s, received %s", expectGvk.Kind, objGvk.Kind)
	}

	if objGvk.Version != expectGvk.Version {
		return fmt.Errorf("expected Version %s, received %s", expectGvk.Version, objGvk.Version)
	}

	if objGvk.Group != expectGvk.Group {
		return fmt.Errorf("expected Group %s, received %s", expectGvk.Group, objGvk.Group)
	}

	return nil
}

func suiteNeedsUpdate(have, found *compliancev1alpha1.ComplianceSuite) bool {
	// comparing spec would miss rename but we probably don't care
	return !reflect.DeepEqual(have.Spec, found.Spec)
}

func scanSettingBindingStatusNeedsUpdate(ssb *compliancev1alpha1.ScanSettingBinding) bool {
	return ssb.Status.Conditions.GetCondition("Ready") == nil || ssb.Status.OutputRef == nil || ssb.Status.OutputRef.Name == ""
}
