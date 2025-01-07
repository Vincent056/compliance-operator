// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1

// DNSStatusApplyConfiguration represents a declarative configuration of the DNSStatus type for use
// with apply.
type DNSStatusApplyConfiguration struct {
	ClusterIP     *string                               `json:"clusterIP,omitempty"`
	ClusterDomain *string                               `json:"clusterDomain,omitempty"`
	Conditions    []OperatorConditionApplyConfiguration `json:"conditions,omitempty"`
}

// DNSStatusApplyConfiguration constructs a declarative configuration of the DNSStatus type for use with
// apply.
func DNSStatus() *DNSStatusApplyConfiguration {
	return &DNSStatusApplyConfiguration{}
}

// WithClusterIP sets the ClusterIP field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ClusterIP field is set to the value of the last call.
func (b *DNSStatusApplyConfiguration) WithClusterIP(value string) *DNSStatusApplyConfiguration {
	b.ClusterIP = &value
	return b
}

// WithClusterDomain sets the ClusterDomain field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ClusterDomain field is set to the value of the last call.
func (b *DNSStatusApplyConfiguration) WithClusterDomain(value string) *DNSStatusApplyConfiguration {
	b.ClusterDomain = &value
	return b
}

// WithConditions adds the given value to the Conditions field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Conditions field.
func (b *DNSStatusApplyConfiguration) WithConditions(values ...*OperatorConditionApplyConfiguration) *DNSStatusApplyConfiguration {
	for i := range values {
		if values[i] == nil {
			panic("nil value passed to WithConditions")
		}
		b.Conditions = append(b.Conditions, *values[i])
	}
	return b
}
