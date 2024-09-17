package utils

import (
	compv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
)

func IsCustomTailoredProfile(tp *compv1alpha1.TailoredProfile) bool {
	return tp.GetAnnotations()[compv1alpha1.CustomProfileAnnotation] == "true"
}
