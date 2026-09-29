package usagegraph

import "github.com/Xsamsx/SBOMber/internal/sourceanalysis"

// A parameter or local declaration in any containing function can hide a
// same-named module function or relative import. Do not add a direct-call
// edge through that identifier.
func shadowedLocalCall(result sourceanalysis.Result, call sourceanalysis.Call) bool {
	if call.Callee == nil {
		return false
	}
	binding := *call.Callee
	if call.Receiver != nil {
		binding = *call.Receiver
	}
	for _, functions := range [][]sourceanalysis.Function{
		result.Functions,
		result.AnonymousFunctions,
	} {
		for _, function := range functions {
			if !anonymousContainsCall(function, call) {
				continue
			}
			if hasName(function.Parameters, binding) ||
				hasName(function.LocalBindings, binding) {
				return true
			}
		}
	}
	return false
}

func hasName(names []string, name string) bool {
	for _, candidate := range names {
		if candidate == name {
			return true
		}
	}
	return false
}
