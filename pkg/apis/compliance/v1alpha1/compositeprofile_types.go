package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type CompositeProfilePayload struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	// +nullable
	// +optional
	// +listType=atomic
	Rules []ProfileRule `json:"rules,omitempty"`
	// +nullable
	// +optional
	// +listType=atomic
	Values []ProfileValue `json:"values,omitempty"`
	// +nullable
	// +optional
	// +listType=atomic
	Profiles []string `json:"profiles,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// CompositeProfile is the Schema for the compositeprofiles API
type CompositeProfile struct {
	metav1.TypeMeta         `json:",inline"`
	metav1.ObjectMeta       `json:"metadata,omitempty"`
	CompositeProfilePayload `json:",inline"`
}

//+kubebuilder:object:root=true

// CompositeProfileList contains a list of CompositeProfile
type CompositeProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CompositeProfile `json:"items"`
}

func init() {
	SchemeBuilder.Register(&CompositeProfile{}, &CompositeProfileList{})
}
