package dashboard

import (
	"context"
	_ "embed"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/admission"

	"github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v0alpha1"
	"github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v1alpha1"
	"github.com/grafana/grafana/apps/dashboard/pkg/apis/dashboard/v2alpha1"
	"github.com/grafana/grafana/pkg/services/dashboards"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ValidateDashboardSpec validates the dashboard spec and throws a detailed error if there are validation errors.
func ValidateDashboardSpec(ctx context.Context, obj runtime.Object, a admission.Attributes) error {
	mode := getFieldValidationMode(a)
	errors := ValidateDashboardSpecByMode(ctx, mode, obj)
	if len(errors) > 0 {
		return dashboards.NewDashboardSpecValidationErr(errors)
	}

	return nil
}

// ValidateDashboardSpecByMode validates the dashboard spec, considering the field validation mode.
func ValidateDashboardSpecByMode(ctx context.Context, mode string, obj runtime.Object) field.ErrorList {
	if mode == metav1.FieldValidationIgnore {
		// We don't want to validate the dashboard spec if the validation is set to ignore.
		return nil
	}

	if mode == metav1.FieldValidationWarn {
		// TODO: not sure how to return warnings
		return nil
	}

	switch v := obj.(type) {
	case *v0alpha1.Dashboard:
		// No-op for v0, we don't care about validating this API.
		return nil
	case *v1alpha1.Dashboard:
		return v1alpha1.ValidateDashboardSpec(v)
	case *v2alpha1.Dashboard:
		return v2alpha1.ValidateDashboardSpec(v)
	}
	return nil
}

func getFieldValidationMode(a admission.Attributes) string {
	var validation string
	switch opts := a.GetOperationOptions().(type) {
	case *metav1.CreateOptions:
		validation = opts.FieldValidation
	case *metav1.UpdateOptions:
		validation = opts.FieldValidation
	default:
		validation = metav1.FieldValidationStrict
	}

	if validation == "" {
		validation = metav1.FieldValidationStrict
	}

	return validation
}
