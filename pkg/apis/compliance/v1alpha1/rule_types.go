package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// RuleIDAnnotationKey exposes the DNS-friendly name of a rule as an annotation.
// This provides a way to link a result to a Rule object.
// TODO(jaosorior): Decide where this actually belongs... should it be
// here or in the compliance-operator?
const RuleIDAnnotationKey = "compliance.openshift.io/rule"

// RuleHideTagAnnotationKey is the annotation used to mark a rule to be hidden from the
// ComplianceCheckResult
const RuleHideTagAnnotationKey = "compliance.openshift.io/hide-tag"

// RuleVariableAnnotationKey store list of xccdf variables used to render the rule
const RuleVariableAnnotationKey = "compliance.openshift.io/rule-variable"

// RuleProfileAnnotationKey is the annotation used to store which profiles are using a particular rule
const RuleProfileAnnotationKey = "compliance.openshift.io/profiles"

const (
	CheckTypePlatform = "Platform"
	CheckTypeNode     = "Node"
	CheckTypeNone     = ""
)

// ScannerTypeEnum is an enum type for the scanner type
type ScannerTypeEnum string

const (
	// ScannerTypeOpenSCAP is the default scanner type
	ScannerTypeOpenSCAP ScannerTypeEnum = "openscap"
	// ScannerTypeCelScanner is the scanner type for the CEL scanner
	ScannerTypeCelScanner ScannerTypeEnum = "cel"
	// ScannerTypeUnknown is the scanner type for an unknown scanner
	ScannerTypeUnknown ScannerTypeEnum = "unknown"
)

// RulePayload defines the structure for rule evaluation
type RulePayload struct {
	// The XCCDF ID
	ID string `json:"id"`
	// The title of the Rule
	Title string `json:"title"`
	// The description of the Rule
	Description string `json:"description,omitempty"`
	// The rationale of the Rule
	Rationale string `json:"rationale,omitempty"`
	// A discretionary warning about the of the Rule
	Warning string `json:"warning,omitempty"`
	// The severity level
	Severity string `json:"severity,omitempty"`
	// Instructions for auditing this specific rule
	Instructions string `json:"instructions,omitempty"`
	// What type of check will this rule execute:
	// Platform, Node or none (represented by an empty string)
	CheckType string `json:"checkType,omitempty"`
	// The Available fixes
	// +nullable
	// +optional
	// +listType=atomic
	AvailableFixes []FixDefinition `json:"availableFixes,omitempty"`
	// ScannerType is the type of scanner that should be used to evaluate this rule
	// Defaults to openscap
	// +kubebuilder:default=openscap
	ScannerType ScannerTypeEnum `json:"scannerType,omitempty"`
	// Expression is the expression that will be evaluated by the scanner
	// This is used by the CEL scanner
	Expression string `json:"expression,omitempty"`
	// Inputs represent the input parameters for the CEL expression
	// +nullable
	// +optional
	// +listType=atomic
	Inputs []InputParameter `json:"inputs,omitempty"`
	// ErrorMessage is the error message that will be displayed if the rule fails
	ErrorMessage string `json:"errorMessage,omitempty"`
}

// InputParameter defines the structure for the inputs used in the CEL expression
type InputParameter struct {
	// The name of the input parameter
	Name string `json:"name"`
	// The type of the input parameter
	Type string `json:"type"`
	// The API group of the resource
	APIGroup string `json:"apiGroup"`
	// The version of the resource
	Version string `json:"version"`
	// The resource type
	Resource string `json:"resource"`
	// The namespace of the resource
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

type RuleResult struct {
	// The XCCDF ID
	ID string `json:"id"`
	// The title of the Rule
	Title string `json:"title"`
	// The description of the Rule
	Description string `json:"description"`
	// The rationale of the Rule
	Rationale string `json:"rationale"`
	// The severity level
	Severity ComplianceCheckResultSeverity `json:"severity"`
	// The result of the rule evaluation
	Status ComplianceCheckStatus `json:"status"`
	// The message of the rule evaluation
	Instructions string `json:"instructions"`
	// Any warnings that the user should be aware about.
	// +nullable
	Warnings []string `json:"warnings,omitempty"`
	// It stores a list of values used by the check
	ValuesUsed []string `json:"valuesUsed,omitempty"`
	// The message of the rule evaluation
	Message string `json:"message"`
}

// +kubebuilder:object:root=true

// Rule is the Schema for the rules API
// +kubebuilder:resource:path=rules,scope=Namespaced
type Rule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	RulePayload `json:",inline"`
}

// FixDefinition Specifies a fix or remediation
// that applies to a rule
type FixDefinition struct {
	// The platform that the fix applies to
	Platform string `json:"platform,omitempty"`
	// An estimate of the potential disruption or operational
	// degradation that this fix will impose in the target system
	Disruption string `json:"disruption,omitempty"`
	// an object that should bring the rule into compliance
	// +kubebuilder:pruning:PreserveUnknownFields
	// +kubebuilder:validation:EmbeddedResource
	// +kubebuilder:validation:nullable
	FixObject *unstructured.Unstructured `json:"fixObject,omitempty"`
}

// +kubebuilder:object:root=true

// RuleList contains a list of Rule
type RuleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Rule `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Rule{}, &RuleList{})
}
