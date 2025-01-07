// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1

// NodeDisruptionPolicyStatusFileApplyConfiguration represents a declarative configuration of the NodeDisruptionPolicyStatusFile type for use
// with apply.
type NodeDisruptionPolicyStatusFileApplyConfiguration struct {
	Path    *string                                              `json:"path,omitempty"`
	Actions []NodeDisruptionPolicyStatusActionApplyConfiguration `json:"actions,omitempty"`
}

// NodeDisruptionPolicyStatusFileApplyConfiguration constructs a declarative configuration of the NodeDisruptionPolicyStatusFile type for use with
// apply.
func NodeDisruptionPolicyStatusFile() *NodeDisruptionPolicyStatusFileApplyConfiguration {
	return &NodeDisruptionPolicyStatusFileApplyConfiguration{}
}

// WithPath sets the Path field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Path field is set to the value of the last call.
func (b *NodeDisruptionPolicyStatusFileApplyConfiguration) WithPath(value string) *NodeDisruptionPolicyStatusFileApplyConfiguration {
	b.Path = &value
	return b
}

// WithActions adds the given value to the Actions field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Actions field.
func (b *NodeDisruptionPolicyStatusFileApplyConfiguration) WithActions(values ...*NodeDisruptionPolicyStatusActionApplyConfiguration) *NodeDisruptionPolicyStatusFileApplyConfiguration {
	for i := range values {
		if values[i] == nil {
			panic("nil value passed to WithActions")
		}
		b.Actions = append(b.Actions, *values[i])
	}
	return b
}
