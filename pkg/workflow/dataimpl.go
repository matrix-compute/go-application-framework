package workflow

import (
	"fmt"
	"net/http"
	"time"
)

type DataImpl struct {
	identifier Identifier
	header     http.Header
	payload    interface{}
}

const (
	Content_type_key     string = "Content-Type"
	Content_location_key string = "Content-Location"
)

func NewDataFromInput(input Data, typeIdentifier Identifier, contentType string, payload interface{}) Data {
	if len(typeIdentifier.Path) <= 0 {
		panic("Given identifier is not a type identifier")
	}

	dataIdentifier := *typeIdentifier
	dataIdentifier.Scheme = "did"

	header := http.Header{
		Content_type_key: {contentType},
	}

	if input != nil {
		// derive fragment from input data if available
		dataIdentifier.Fragment = input.GetIdentifier().Fragment

		// derive content location from input
		if loc, err := input.GetMetaData(Content_location_key); err == nil {
			header.Add(Content_location_key, loc)
		}
	} else {
		// generate time based fragment
		dataIdentifier.Fragment = fmt.Sprintf("%d", time.Now().Nanosecond())
	}

	output := &DataImpl{
		identifier: &dataIdentifier,
		header:     header,
		payload:    payload,
	}

	return output
}

func NewData(id Identifier, contentType string, payload interface{}) Data {
	output := NewDataFromInput(nil, id, contentType, payload)
	return output
}

func (d *DataImpl) SetMetaData(key string, value string) {
	d.header[key] = []string{value}
}

func (d *DataImpl) GetMetaData(key string) (string, error) {
	var value string
	err := fmt.Errorf("Key '%s' not found!", key)
	if values, ok := d.header[key]; ok {
		if len(values) > 0 {
			value = values[0]
			err = nil
		}
	}
	return value, err
}

func (d *DataImpl) SetPayload(payload interface{}) {
	d.payload = payload
}

func (d *DataImpl) GetPayload() interface{} {
	return d.payload
}

func (d *DataImpl) GetIdentifier() Identifier {
	return d.identifier
}

func (d *DataImpl) GetContentType() string {
	result, _ := d.GetMetaData(Content_type_key)
	return result
}

func (d *DataImpl) GetContentLocation() string {
	result, _ := d.GetMetaData(Content_location_key)
	return result
}

func (d *DataImpl) SetContentLocation(location string) {
	d.SetMetaData(Content_location_key, location)
}

func (d *DataImpl) String() string {
	return fmt.Sprintf("{DataImpl, id: \"%s\", content-type: \"%s\"}", d.identifier.String(), d.GetContentType())
}
