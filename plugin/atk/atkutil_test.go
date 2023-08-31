package atk

import "testing"

func TestAtk_validRequest(t *testing.T) {
	type fields struct {
		magni   int
		zoneip4 string
		zoneip6 string
		ip6NS   string
		ip4NS   string
		ip6Addr string
		ip4Addr string
	}
	type args struct {
		qname string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
	}{
		{name: "test1",
			fields: fields{
				magni:   10,
				zoneip4: "comm.n64.top",
				zoneip6: "v6.atk.top",
				ip6NS:   "ns.n64.top",
				ip6Addr: "fe80::",
				ip4Addr: "1.2.3.4",
			},
			args: args{
				qname: "comm.n64.top",
			},
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := Atk{
				magni:   tt.fields.magni,
				zoneip4: tt.fields.zoneip4,
				zoneip6: tt.fields.zoneip6,
				ip6NS:   tt.fields.ip6NS,
				ip4NS:   tt.fields.ip4NS,
				ip6Addr: tt.fields.ip6Addr,
				ip4Addr: tt.fields.ip4Addr,
			}
			if got := a.validRequest(tt.args.qname); got != tt.want {
				t.Errorf("validRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}
