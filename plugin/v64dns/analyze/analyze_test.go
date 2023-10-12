package analyze

import (
	"ohmydns2/plugin/v64dns/analyze/pb"
	"testing"
)

func TestAnalyzer_go2py(t *testing.T) {
	type fields struct {
		Graphtype  string
		Graphuri   string
		GraphUser  string
		GraphPass  string
		IsA        bool
		grpcClient pb.GrpcServiceClient
	}
	type args struct {
		i []string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{"test",
			fields{
				Graphtype: "neo4j",
				Graphuri:  "neo4j+s://600c8c12.databases.neo4j.io:7687",
				GraphUser: "neo4j",
				GraphPass: "5PvtszWJ7ru4hyBTKO9mGnavOJETTGhJYQIeC5SzmPQ",
				IsA:       true,
			},
			args{i: []string{"1.1.1.1", "2001::1"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			NewAnalyzer(tt.fields.Graphtype, tt.fields.Graphuri, tt.fields.GraphUser, tt.fields.GraphPass)
			A.Go2py(tt.args.i)
		})
	}
}
