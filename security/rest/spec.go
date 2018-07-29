package rest

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/go-openapi/spec"
	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
)

// HandlerFunc writes the spec as json
func HandlerFunc(paths spec.Paths) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		definitions := make(map[string]spec.Schema)
		securityDefinitions := make(map[string]*spec.SecurityScheme)
		securityDefinitions["cookieAuth"] = &spec.SecurityScheme{
			SecuritySchemeProps: spec.SecuritySchemeProps{
				Type: "apiKey",
				Name: "c",
				In:   "cookie",
			},
		}
		// swagger
		swagger := &spec.Swagger{
			SwaggerProps: spec.SwaggerProps{
				Swagger: "2.0",
				Paths:   &paths,
				Info: &spec.Info{
					InfoProps: spec.InfoProps{
						Title: "arkavo",
					},
				},
				Definitions: definitions,
				Security: []map[string][]string{
					{"cookieAuth": {}},
				},
				SecurityDefinitions: securityDefinitions,
			},
		}
		s, err := json.Marshal(swagger)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write(s)
	}
}

// ValidationError with JSON tags
type ValidationError struct {
	Property string `json:"property,omitempty"`
	Rule     string `json:"rule,omitempty"`
}

// ValidationErrors returned to the user
type ValidationErrors []ValidationError

func (e ValidationErrors) Error() string {
	var m string
	for _, v := range e {
		m += fmt.Sprint(v)
	}
	return m
}

// ValidateParameterQueryAction query parameter for actions, no value, not required
func ValidateParameterQueryAction(r http.Request, ps ...spec.Parameter) string {
	var v string
	q := map[string][]string(r.URL.Query())
	for _, p := range ps {
		// query parameters with no value
		if p.In == "query" && p.AllowEmptyValue && !p.Required && q[p.ParamProps.Name] != nil {
			v = p.ParamProps.Name
			break
		}
	}
	return v
}

// ValidateParameter path and query parameters
func ValidateParameter(r http.Request, p spec.Parameter) (string, error) {
	var errs ValidationErrors
	valid := true
	v := r.Form.Get(p.ParamProps.Name)
	// path with query
	if p.In == "path" && strings.Contains(v, "?") {
		v = strings.Split(v, "?")[0]
	}
	// query
	if p.In == "query" {
		q := map[string][]string(r.URL.Query())
		if q[p.ParamProps.Name] != nil {
			v = p.ParamProps.Name
		}
	}
	if v == "" && p.ParamProps.Required {
		errs = append(errs, ValidationError{
			Property: p.ParamProps.Name,
			Rule:     "Required",
		})
		valid = false
	}
	if p.ParamProps.Schema == nil {
		return v, nil
	}
	optional := v == ""
	if p.ParamProps.Schema.MinLength != nil && int64(len(v)) < *p.ParamProps.Schema.MinLength {
		errs = append(errs, ValidationError{
			Property: p.ParamProps.Name,
			Rule:     "MinLength",
		})
		valid = optional
	}
	if p.ParamProps.Schema.MaxLength != nil && int64(len(v)) > *p.ParamProps.Schema.MaxLength {
		errs = append(errs, ValidationError{
			Property: p.ParamProps.Name,
			Rule:     "MaxLength",
		})
		valid = optional
	}
	if !valid {
		return "", errs
	}
	return v, nil
}

// Validate body parameter
func Validate(r *http.Request, o *spec.Operation, pb proto.Message) error {
	var errs ValidationErrors
	for _, p := range o.Parameters {
		valid := true
		switch p.In {
		case "body":
			valid = "application/json" == r.Header.Get("content-type")
			if !valid {
				errs = append(errs, ValidationError{
					Property: "content-type",
					Rule:     "JSON",
				})
				break
			}
			err := jsonpb.Unmarshal(r.Body, pb)
			valid = err == nil
			if !valid {
				log.Println(err)
				errs = append(errs, ValidationError{
					Property: "body",
					Rule:     "Unmarshal",
				})
				break
			}
			marshaller := jsonpb.Marshaler{}
			j, _ := marshaller.MarshalToString(pb)
			var jf map[string]*json.RawMessage
			json.Unmarshal([]byte(j), &jf)
			// required
			for _, require := range p.Schema.Required {
				if jf[require] == nil {
					valid = false
					errs = append(errs, ValidationError{
						Property: require,
						Rule:     "Required",
					})
				}
			}
		}
		if !valid {
			return errs
		}
	}
	return nil
}

// BodyParameter body parameter with Required true
func BodyParameter(s spec.Schema) spec.Parameter {
	return spec.Parameter{
		ParamProps: spec.ParamProps{
			Name:     "body",
			In:       "body",
			Required: true,
			Schema:   &s,
		},
	}
}
