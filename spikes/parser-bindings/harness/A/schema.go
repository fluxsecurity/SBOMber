package main

type Result struct {
	Fixture    string       `json:"fixture"`
	Language   string       `json:"language"`
	HasError   bool         `json:"hasError"`
	Imports    []Import     `json:"imports"`
	Calls      []Call       `json:"calls"`
	Functions  []Function   `json:"functions"`
	Unresolved []Unresolved `json:"unresolved"`
}

type Import struct {
	Specifier string `json:"specifier"`
	Kind      string `json:"kind"`
	Local     string `json:"local"`
	Imported  string `json:"imported"`
	TypeOnly  bool   `json:"typeOnly"`
	Line      int    `json:"line"`
	Column    int    `json:"column"`
}

type Call struct {
	Callee   *string `json:"callee"`
	Receiver *string `json:"receiver"`
	Line     int     `json:"line"`
	Column   int     `json:"column"`
	Note     string  `json:"note,omitempty"`
}

type Function struct {
	Name     string `json:"name"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
	Exported bool   `json:"exported"`
}

type Unresolved struct {
	Kind       string `json:"kind"`
	Expression string `json:"expression"`
	Line       int    `json:"line"`
	Column     int    `json:"column"`
	Reason     string `json:"reason"`
}

func newResult(fixture, language string) Result {
	return Result{
		Fixture:    fixture,
		Language:   language,
		Imports:    []Import{},
		Calls:      []Call{},
		Functions:  []Function{},
		Unresolved: []Unresolved{},
	}
}
