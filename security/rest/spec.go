package rest

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"reflect"
	"regexp"
	"strings"

	"github.com/arkavo-com/secure-rest-server/security/configuration"
	"github.com/go-openapi/spec"
	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
)

// HandlerFunc writes the spec as json
func HandlerFunc(paths spec.Paths) http.HandlerFunc {
	definitions := definitions(paths)
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
			Host:    configuration.Server.Host,
			Schemes: []string{"https"},
			Info: &spec.Info{
				InfoProps: spec.InfoProps{
					Title:   "arkavo",
					Version: "1.0.0",
				},
			},
			Paths:       &paths,
			Definitions: definitions,
			Security: []map[string][]string{
				{"cookieAuth": {}},
			},
			SecurityDefinitions: securityDefinitions,
		},
	}
	s, err := json.Marshal(swagger)
	return func(w http.ResponseWriter, r *http.Request) {
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write(s)
	}
}

func definitions(paths spec.Paths) map[string]spec.Schema {
	definitions := make(map[string]spec.Schema)
	for _, pathItem := range paths.Paths {
		var operations []*spec.Operation
		operations = append(operations, pathItem.Get, pathItem.Put, pathItem.Delete, pathItem.Post)
		for _, operation := range operations {
			if operation == nil {
				continue
			}
			for _, parameter := range operation.Parameters {
				if parameter.Schema == nil {
					continue
				}
				definitions[operation.ID+"-"+parameter.Name] = *(parameter.Schema)
				parameter.Ref = spec.MustCreateRef("#/definitions/" + operation.ID + "-" + parameter.Name)
				parameter.Schema = nil
			}
		}
	}
	return definitions
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
			for k, schema := range p.Schema.Properties {
				if schema.Type.Contains("string") {
					var v string
					err = json.Unmarshal(*jf[k], &v)
					if err != nil {
						log.Println(v, err)
						errs = append(errs, ValidationError{
							Property: k,
							Rule:     "Unmarshal",
						})
					}
					if schema.MinLength != nil && int64(len(v)) < *schema.MinLength {
						errs = append(errs, ValidationError{
							Property: k,
							Rule:     "MinLength",
						})
						valid = false
					}
					if schema.MaxLength != nil && int64(len(v)) > *schema.MaxLength {
						errs = append(errs, ValidationError{
							Property: k,
							Rule:     "MaxLength",
						})
						valid = false
					}
					if schema.Pattern != "" {
						pattern := regexp.MustCompile(schema.Pattern)
						if !pattern.MatchString(v) {
							errs = append(errs, ValidationError{
								Property: k,
								Rule:     "Pattern",
							})
							valid = false
						}
					}
				}
				if schema.Type.Contains("array") {
					var a []string
					err = json.Unmarshal(*jf[k], &a)
					if err != nil {
						log.Println(a, err)
						errs = append(errs, ValidationError{
							Property: k,
							Rule:     "Unmarshal",
						})
					}
					if schema.MinItems != nil && int64(len(a)) < *schema.MinItems {
						errs = append(errs, ValidationError{
							Property: k,
							Rule:     "MinItems",
						})
						valid = false
					}
				}
				// reset read only fields
				if schema.SwaggerSchemaProps.ReadOnly {
					if "" != schema.SwaggerSchemaProps.Discriminator {
						v := reflect.ValueOf(pb).Elem().FieldByName(schema.SwaggerSchemaProps.Discriminator)
						if v.IsValid() {
							switch k := v.Kind(); k {
							case reflect.String:
								v.SetString("")
							case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
								v.SetInt(0)
							}
						}
					}
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

// ReadResponses responses for read operation
func ReadResponses() *spec.Responses {
	return &spec.Responses{
		ResponsesProps: spec.ResponsesProps{
			StatusCodeResponses: map[int]spec.Response{
				http.StatusOK: {
					ResponseProps: spec.ResponseProps{
						Description: http.StatusText(http.StatusOK),
					},
				},
				http.StatusBadRequest: {
					ResponseProps: spec.ResponseProps{
						Description: http.StatusText(http.StatusBadRequest),
					},
				},
				http.StatusUnauthorized: {
					ResponseProps: spec.ResponseProps{
						Description: http.StatusText(http.StatusUnauthorized),
					},
				},
				http.StatusForbidden: {
					ResponseProps: spec.ResponseProps{
						Description: http.StatusText(http.StatusForbidden),
					},
				},
				http.StatusNotFound: {
					ResponseProps: spec.ResponseProps{
						Description: http.StatusText(http.StatusNotFound),
					},
				},
			},
		},
	}
}

// CreateResponses responses for create operation
func CreateResponses() *spec.Responses {
	return &spec.Responses{
		ResponsesProps: spec.ResponsesProps{
			StatusCodeResponses: map[int]spec.Response{
				http.StatusCreated: {
					ResponseProps: spec.ResponseProps{
						Description: http.StatusText(http.StatusCreated),
					},
				},
				http.StatusBadRequest: {
					ResponseProps: spec.ResponseProps{
						Description: http.StatusText(http.StatusBadRequest),
					},
				},
				http.StatusUnauthorized: {
					ResponseProps: spec.ResponseProps{
						Description: http.StatusText(http.StatusUnauthorized),
					},
				},
				http.StatusForbidden: {
					ResponseProps: spec.ResponseProps{
						Description: http.StatusText(http.StatusForbidden),
					},
				},
			},
		},
	}
}

// UpdateResponses responses for update operation
func UpdateResponses() *spec.Responses {
	return &spec.Responses{
		ResponsesProps: spec.ResponsesProps{
			StatusCodeResponses: map[int]spec.Response{
				http.StatusOK: {
					ResponseProps: spec.ResponseProps{
						Description: http.StatusText(http.StatusOK),
					},
				},
				http.StatusNotModified: {
					ResponseProps: spec.ResponseProps{
						Description: http.StatusText(http.StatusNotModified),
					},
				},
				http.StatusBadRequest: {
					ResponseProps: spec.ResponseProps{
						Description: http.StatusText(http.StatusBadRequest),
					},
				},
				http.StatusUnauthorized: {
					ResponseProps: spec.ResponseProps{
						Description: http.StatusText(http.StatusUnauthorized),
					},
				},
				http.StatusForbidden: {
					ResponseProps: spec.ResponseProps{
						Description: http.StatusText(http.StatusForbidden),
					},
				},
				http.StatusNotFound: {
					ResponseProps: spec.ResponseProps{
						Description: http.StatusText(http.StatusNotFound),
					},
				},
			},
		},
	}
}

// DeleteResponses responses for delete operation
func DeleteResponses() *spec.Responses {
	return &spec.Responses{
		ResponsesProps: spec.ResponsesProps{
			StatusCodeResponses: map[int]spec.Response{
				http.StatusNoContent: {
					ResponseProps: spec.ResponseProps{
						Description: http.StatusText(http.StatusNoContent),
					},
				},
				http.StatusUnauthorized: {
					ResponseProps: spec.ResponseProps{
						Description: http.StatusText(http.StatusUnauthorized),
					},
				},
				http.StatusForbidden: {
					ResponseProps: spec.ResponseProps{
						Description: http.StatusText(http.StatusForbidden),
					},
				},
				http.StatusNotFound: {
					ResponseProps: spec.ResponseProps{
						Description: http.StatusText(http.StatusNotFound),
					},
				},
			},
		},
	}
}
