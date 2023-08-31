package prober

import (
	"context"
	"ohmydns2/plugin/pkg/request"
)

// MetadataCollector is a plugin that can retrieve metadata functions from all metadata providing plugins
type ProberMetadataCollector interface {
	Collect(context.Context, request.HTTPRequest) context.Context
}
