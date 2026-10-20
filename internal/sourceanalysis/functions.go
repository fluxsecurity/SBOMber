package sourceanalysis

// EnclosingFunction returns the smallest named function range containing the call.
func EnclosingFunction(
	functions []Function,
	call Call,
) (Function, bool) {
	var selected Function
	found := false

	for _, function := range functions {
		if !functionContainsPosition(function, call.Line, call.Column) {
			continue
		}

		if !found || functionIsMoreSpecific(function, selected) {
			selected = function
			found = true
		}
	}

	return selected, found
}

func functionContainsPosition(
	function Function,
	line int,
	column int,
) bool {
	if function.EndLine == 0 {
		return false
	}

	if line < function.Line || line > function.EndLine {
		return false
	}
	if line == function.Line && column < function.Column {
		return false
	}
	if line == function.EndLine && column >= function.EndColumn {
		return false
	}

	return true
}

func functionIsMoreSpecific(
	candidate Function,
	current Function,
) bool {
	if candidate.Line != current.Line {
		return candidate.Line > current.Line
	}
	if candidate.Column != current.Column {
		return candidate.Column > current.Column
	}
	if candidate.EndLine != current.EndLine {
		return candidate.EndLine < current.EndLine
	}
	if candidate.EndColumn != current.EndColumn {
		return candidate.EndColumn < current.EndColumn
	}

	return candidate.Name < current.Name
}
