package sourceanalysis

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

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

			kind := "esm_default"
			if statementTypeOnly {
				kind = "esm_type_only"
			}

			result.Imports = append(
				result.Imports,
				Import{
					Specifier: specifier,
					Kind:      kind,
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

	if len(importClauses) == 0 {
		// import "pkg" loads the module for its side effects only.
		// Nothing can be called through it, but the package is imported.
		line, column := nodeLocation(source, statement)
		result.Imports = append(
			result.Imports,
			Import{
				Specifier: specifier,
				Kind:      "esm_side_effect",
				TypeOnly:  false,
				Line:      line,
				Column:    column,
			},
		)
		return nil
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

		typeOnly := statementTypeOnly ||
			nodeHasDirectChildType(
				importSpecifier,
				"type",
			)

		kind := "esm_named"
		if typeOnly {
			kind = "esm_type_only"
		}

		result.Imports = append(
			result.Imports,
			Import{
				Specifier: specifier,
				Kind:      kind,
				Local:     localNode.Utf8Text(source),
				Imported:  nameNode.Utf8Text(source),
				TypeOnly:  typeOnly,
				Line:      line,
				Column:    column,
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
	declarationLine, declarationColumn := nodeLocation(source, declaration)
	endLine, endColumn := nodeEndLocation(
		source,
		declaration,
	)

	exported := false
	parent := declaration.Parent()

	if parent != nil &&
		parent.Kind() == "export_statement" {
		exported = true
	}

	result.Functions = append(
		result.Functions,
		Function{
			Name:          name.Utf8Text(source),
			Line:          line,
			Column:        column,
			EndLine:       endLine,
			EndColumn:     endColumn,
			NodeLine:      declarationLine,
			NodeColumn:    declarationColumn,
			Parameters:    parameterNames(declaration, source),
			LocalBindings: localBindingNames(declaration, source),
			Exported:      exported,
		},
	)

	return nil
}

func sortResult(result *Result) {
	sort.SliceStable(
		result.RouteHandlers,
		func(left, right int) bool {
			a := result.RouteHandlers[left]
			b := result.RouteHandlers[right]

			if a.Line != b.Line {
				return a.Line < b.Line
			}
			if a.Column != b.Column {
				return a.Column < b.Column
			}
			if a.Receiver != b.Receiver {
				return a.Receiver < b.Receiver
			}
			if a.Method != b.Method {
				return a.Method < b.Method
			}

			return a.Function < b.Function
		},
	)

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

func extractFile(
	fixturePath string,
) (Result, error) {
	resultLanguage, err := languageForPath(
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

	compiled, err := compiledUsageQuery(resultLanguage)
	if err != nil {
		return Result{}, err
	}
	language := compiled.language

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

	query := compiled.query

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
					"require.arguments",
				),
				source,
			)

		case captureNode(
			match,
			captureNames,
			"reexport.statement",
		) != nil:
			err = appendReexports(
				&result,
				captureNode(
					match,
					captureNames,
					"reexport.statement",
				),
				captureNode(
					match,
					captureNames,
					"reexport.source",
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

	if err := appendImportRequireClauses(
		&result,
		root,
		source,
	); err != nil {
		return Result{}, err
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

	if err := appendRouteHandlers(
		&result,
		root,
		source,
	); err != nil {
		return Result{}, err
	}

	appendAnonymousFunctionRanges(&result, root, source)

	resolveFunctionExports(&result, root, source)

	sortResult(&result)

	return result, nil
}

// usageQueries caches the compiled usage query per grammar. Compiling the
// query costs far more than parsing a typical file, and a compiled query is
// read-only, so every file of a language shares one.
var usageQueries = struct {
	sync.Mutex
	byLanguage map[string]compiledQuery
}{byLanguage: make(map[string]compiledQuery)}

type compiledQuery struct {
	language *treesitter.Language
	query    *treesitter.Query
}

func compiledUsageQuery(languageName string) (compiledQuery, error) {
	usageQueries.Lock()
	defer usageQueries.Unlock()

	if cached, ok := usageQueries.byLanguage[languageName]; ok {
		return cached, nil
	}
	language, err := treeSitterLanguage(languageName)
	if err != nil {
		return compiledQuery{}, err
	}
	query, queryErr := treesitter.NewQuery(language, string(usageQuery))
	if queryErr != nil {
		return compiledQuery{}, fmt.Errorf("compile usage query: %v", queryErr)
	}
	compiled := compiledQuery{language: language, query: query}
	usageQueries.byLanguage[languageName] = compiled
	return compiled, nil
}
