package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	treesitter "github.com/tree-sitter/go-tree-sitter"
)

func captureNode(
	match *treesitter.QueryMatch,
	captureNames []string,
	name string,
) *treesitter.Node {
	if match == nil {
		return nil
	}

	for index := range match.Captures {
		capture := &match.Captures[index]

		if int(capture.Index) >= len(captureNames) {
			continue
		}

		if captureNames[capture.Index] == name {
			return &capture.Node
		}
	}

	return nil
}

func readUsageQuery() ([]byte, error) {
	candidates := []string{
		"queries/usage.scm",
		"../../queries/usage.scm",
	}

	for _, candidate := range candidates {
		data, err := os.ReadFile(candidate)
		if err == nil {
			return data, nil
		}

		if !os.IsNotExist(err) {
			return nil, fmt.Errorf(
				"read usage query %q: %w",
				candidate,
				err,
			)
		}
	}

	return nil, fmt.Errorf(
		"usage query not found; tried %v",
		candidates,
	)
}

func appendESMImports(
	result *Result,
	statement *treesitter.Node,
	sourceNode *treesitter.Node,
	source []byte,
) error {
	if statement == nil || sourceNode == nil {
		return fmt.Errorf(
			"ESM import match is missing required captures",
		)
	}

	specifier, err := unquoteJavaScriptString(
		sourceNode.Utf8Text(source),
	)
	if err != nil {
		return err
	}

	statementTypeOnly := nodeHasDirectChildType(
		statement,
		"type",
	)

	if err := appendESMNamespaceImports(
		result,
		statement,
		source,
		specifier,
		statementTypeOnly,
	); err != nil {
		return err
	}

	importClauses := collectNodesByType(
		statement,
		"import_clause",
	)

	for _, importClause := range importClauses {
		for index := uint(0); index < importClause.ChildCount(); index++ {
			child := importClause.Child(index)

			if child == nil ||
				child.Kind() != "identifier" {
				continue
			}

			line, column := nodeLocation(source, child)

			result.Imports = append(
				result.Imports,
				Import{
					Specifier: specifier,
					Kind:      "esm_default",
					Local:     child.Utf8Text(source),
					Imported:  "default",
					TypeOnly:  statementTypeOnly,
					Line:      line,
					Column:    column,
				},
			)

			break
		}
	}

	importSpecifiers := collectNodesByType(
		statement,
		"import_specifier",
	)

	for _, importSpecifier := range importSpecifiers {
		nameNode := importSpecifier.ChildByFieldName("name")
		if nameNode == nil {
			return fmt.Errorf(
				"import specifier at bytes %d-%d has no name",
				importSpecifier.StartByte(),
				importSpecifier.EndByte(),
			)
		}

		aliasNode := importSpecifier.ChildByFieldName("alias")
		localNode := nameNode

		if aliasNode != nil {
			localNode = aliasNode
		}

		line, column := nodeLocation(source, localNode)

		result.Imports = append(
			result.Imports,
			Import{
				Specifier: specifier,
				Kind:      "esm_named",
				Local:     localNode.Utf8Text(source),
				Imported:  nameNode.Utf8Text(source),
				TypeOnly: statementTypeOnly ||
					nodeHasDirectChildType(
						importSpecifier,
						"type",
					),
				Line:   line,
				Column: column,
			},
		)
	}

	return nil
}

func appendDirectCall(
	result *Result,
	site *treesitter.Node,
	name *treesitter.Node,
	receiver *treesitter.Node,
	property *treesitter.Node,
	source []byte,
) error {
	if site == nil {
		return fmt.Errorf(
			"call match has no call.site capture",
		)
	}

	line, column := nodeLocation(source, site)

	call := Call{
		Line:   line,
		Column: column,
	}

	switch {
	case name != nil:
		call.Callee = stringPointer(
			name.Utf8Text(source),
		)

	case receiver != nil && property != nil:
		call.Receiver = stringPointer(
			receiver.Utf8Text(source),
		)
		call.Callee = stringPointer(
			property.Utf8Text(source),
		)

	default:
		return fmt.Errorf(
			"call at bytes %d-%d has no supported callee",
			site.StartByte(),
			site.EndByte(),
		)
	}

	result.Calls = append(result.Calls, call)

	return nil
}

func appendIIFECall(
	result *Result,
	site *treesitter.Node,
	source []byte,
) error {
	if site == nil {
		return fmt.Errorf(
			"IIFE match has no call.iife_site capture",
		)
	}

	line, column := nodeLocation(source, site)

	result.Calls = append(
		result.Calls,
		Call{
			Callee:   nil,
			Receiver: nil,
			Line:     line,
			Column:   column,
			Note:     "immediately-invoked result",
		},
	)

	return nil
}

func appendFunction(
	result *Result,
	declaration *treesitter.Node,
	name *treesitter.Node,
	source []byte,
) error {
	if declaration == nil || name == nil {
		return fmt.Errorf(
			"function match is missing required captures",
		)
	}

	line, column := nodeLocation(source, name)

	exported := false
	parent := declaration.Parent()

	if parent != nil &&
		parent.Kind() == "export_statement" {
		exported = true
	}

	result.Functions = append(
		result.Functions,
		Function{
			Name:     name.Utf8Text(source),
			Line:     line,
			Column:   column,
			Exported: exported,
		},
	)

	return nil
}

func sortResult(result *Result) {
	sort.SliceStable(
		result.Imports,
		func(left, right int) bool {
			a := result.Imports[left]
			b := result.Imports[right]

			if a.Line != b.Line {
				return a.Line < b.Line
			}

			if a.Column != b.Column {
				return a.Column < b.Column
			}

			if a.Local != b.Local {
				return a.Local < b.Local
			}

			return a.Imported < b.Imported
		},
	)

	sort.SliceStable(
		result.Calls,
		func(left, right int) bool {
			a := result.Calls[left]
			b := result.Calls[right]

			if a.Line != b.Line {
				return a.Line < b.Line
			}

			if a.Column != b.Column {
				return a.Column < b.Column
			}

			if (a.Note == "") != (b.Note == "") {
				return a.Note == ""
			}

			aName := ""
			bName := ""

			if a.Callee != nil {
				aName = *a.Callee
			}

			if b.Callee != nil {
				bName = *b.Callee
			}

			return aName < bName
		},
	)

	sort.SliceStable(
		result.Functions,
		func(left, right int) bool {
			a := result.Functions[left]
			b := result.Functions[right]

			if a.Line != b.Line {
				return a.Line < b.Line
			}

			if a.Column != b.Column {
				return a.Column < b.Column
			}

			return a.Name < b.Name
		},
	)

	sort.SliceStable(
		result.Unresolved,
		func(left, right int) bool {
			a := result.Unresolved[left]
			b := result.Unresolved[right]

			if a.Line != b.Line {
				return a.Line < b.Line
			}

			if a.Column != b.Column {
				return a.Column < b.Column
			}

			return a.Expression < b.Expression
		},
	)
}

func extractFixture(
	fixturePath string,
) (Result, error) {
	resultLanguage, err := resultLanguageForPath(
		fixturePath,
	)
	if err != nil {
		return Result{}, err
	}

	result := newResult(
		filepath.Base(fixturePath),
		resultLanguage,
	)

	source, err := os.ReadFile(fixturePath)
	if err != nil {
		return Result{}, fmt.Errorf(
			"read fixture: %w",
			err,
		)
	}

	language, err := languageForFixture(fixturePath)
	if err != nil {
		return Result{}, err
	}

	parser := treesitter.NewParser()
	if parser == nil {
		return Result{}, fmt.Errorf(
			"parser creation returned nil",
		)
	}
	defer parser.Close()

	if err := parser.SetLanguage(language); err != nil {
		return Result{}, fmt.Errorf(
			"set parser language: %w",
			err,
		)
	}

	tree := parser.Parse(source, nil)
	if tree == nil {
		return Result{}, fmt.Errorf(
			"parser returned nil tree",
		)
	}
	defer tree.Close()

	root := tree.RootNode()
	if root == nil {
		return Result{}, fmt.Errorf(
			"tree returned nil root node",
		)
	}

	result.HasError = root.HasError()

	// Preserve Candidate B behaviour:
	// syntax-error fixtures report HasError but do not
	// attempt semantic extraction.
	if result.HasError {
		return result, nil
	}

	querySource, err := readUsageQuery()
	if err != nil {
		return Result{}, err
	}

	query, queryErr := treesitter.NewQuery(
		language,
		string(querySource),
	)
	if queryErr != nil {
		return Result{}, fmt.Errorf(
			"compile usage query: %v",
			queryErr,
		)
	}
	defer query.Close()

	cursor := treesitter.NewQueryCursor()
	if cursor == nil {
		return Result{}, fmt.Errorf(
			"query cursor creation returned nil",
		)
	}
	defer cursor.Close()

	captureNames := query.CaptureNames()
	matches := cursor.Matches(
		query,
		root,
		source,
	)

	// QueryMatches.Next() performs text-predicate filtering
	// internally in go-tree-sitter v0.25.0.
	for {
		match := matches.Next()
		if match == nil {
			break
		}

		switch {
		case captureNode(
			match,
			captureNames,
			"import.statement",
		) != nil:
			err = appendESMImports(
				&result,
				captureNode(
					match,
					captureNames,
					"import.statement",
				),
				captureNode(
					match,
					captureNames,
					"import.source",
				),
				source,
			)

		case captureNode(
			match,
			captureNames,
			"require.statement",
		) != nil:
			err = appendRequireImports(
				&result,
				captureNode(
					match,
					captureNames,
					"require.statement",
				),
				captureNode(
					match,
					captureNames,
					"require.source",
				),
				source,
			)

		case captureNode(
			match,
			captureNames,
			"dynamic.statement",
		) != nil:
			err = appendDynamicImport(
				&result,
				captureNode(
					match,
					captureNames,
					"dynamic.statement",
				),
				captureNode(
					match,
					captureNames,
					"dynamic.arguments",
				),
				source,
			)

		case captureNode(
			match,
			captureNames,
			"call.iife_site",
		) != nil:
			err = appendIIFECall(
				&result,
				captureNode(
					match,
					captureNames,
					"call.iife_site",
				),
				source,
			)

		case captureNode(
			match,
			captureNames,
			"call.site",
		) != nil:
			err = appendDirectCall(
				&result,
				captureNode(
					match,
					captureNames,
					"call.site",
				),
				captureNode(
					match,
					captureNames,
					"call.name",
				),
				captureNode(
					match,
					captureNames,
					"call.receiver",
				),
				captureNode(
					match,
					captureNames,
					"call.property",
				),
				source,
			)

		case captureNode(
			match,
			captureNames,
			"function.decl",
		) != nil:
			err = appendFunction(
				&result,
				captureNode(
					match,
					captureNames,
					"function.decl",
				),
				captureNode(
					match,
					captureNames,
					"function.name",
				),
				source,
			)
		}

		if err != nil {
			return Result{}, err
		}
	}

	if err := appendStructuralCalls(
		&result,
		root,
		source,
	); err != nil {
		return Result{}, err
	}

	if err := appendAdditionalFunctions(
		&result,
		root,
		source,
	); err != nil {
		return Result{}, err
	}

	sortResult(&result)

	return result, nil
}

func runExtract(fixturePath string) error {
	result, err := extractFixture(fixturePath)
	if err != nil {
		return err
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)

	if err := encoder.Encode(result); err != nil {
		return fmt.Errorf(
			"encode extraction result: %w",
			err,
		)
	}

	return nil
}
