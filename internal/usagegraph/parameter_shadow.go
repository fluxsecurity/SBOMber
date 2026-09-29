package usagegraph

import "github.com/Xsamsx/SBOMber/internal/sourceanalysis"

// A parameter in any containing function can hide a same-named function or
// relative import. Do not add a direct-call edge through that identifier.
func shadowedParameterCall(result sourceanalysis.Result, call sourceanalysis.Call) bool {
	if call.Callee == nil {
		return false
	}
	binding := *call.Callee
	if call.Receiver != nil {
		binding = *call.Receiver
	}
	for _, function := range result.Functions {
		if anonymousContainsCall(function, call) &&
			hasParameter(function.Parameters, binding) {
			return true
		}
	}
	for _, function := range result.AnonymousFunctions {
		if anonymousContainsCall(function, call) &&
			hasParameter(function.Parameters, binding) {
			return true
		}
	}
	return false
}

func hasParameter(parameters []string, name string) bool {
	for _, parameter := range parameters {
		if parameter == name {
			return true
		}
	}
	return false
}
