// Code generated by go-swagger; DO NOT EDIT.

package daemon

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"io"
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/models"
)

// NewPatchConfigParams creates a new PatchConfigParams object
// with the default values initialized.
func NewPatchConfigParams() PatchConfigParams {
	var ()
	return PatchConfigParams{}
}

// PatchConfigParams contains all the bound params for the patch config operation
// typically these are obtained from a http.Request
//
// swagger:parameters PatchConfig
type PatchConfigParams struct {

	// HTTP Request Object
	HTTPRequest *http.Request

	/*
	  Required: true
	  In: body
	*/
	Configuration *models.Configuration
}

// BindRequest both binds and validates a request, it assumes that complex things implement a Validatable(strfmt.Registry) error interface
// for simple values it will use straight method calls
func (o *PatchConfigParams) BindRequest(r *http.Request, route *middleware.MatchedRoute) error {
	var res []error
	o.HTTPRequest = r

	if runtime.HasBody(r) {
		defer r.Body.Close()
		var body models.Configuration
		if err := route.Consumer.Consume(r.Body, &body); err != nil {
			if err == io.EOF {
				res = append(res, errors.Required("configuration", "body"))
			} else {
				res = append(res, errors.NewParseError("configuration", "body", "", err))
			}

		} else {
			if err := body.Validate(route.Formats); err != nil {
				res = append(res, err)
			}

			if len(res) == 0 {
				o.Configuration = &body
			}
		}

	} else {
		res = append(res, errors.Required("configuration", "body"))
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
