package rtest

import (
	"context"
	"encoding/csv"
	"fmt"
	"github.com/miekg/dns"
	"net"
	"ohmydns2/plugin/pkg/request"
	"os"
	"strings"
	"time"
)

type Rtest struct {
	addr     string
	ns       string
	datachan chan []string
}

func (r Rtest) ServeDNS(ctx context.Context, writer dns.ResponseWriter, msg *dns.Msg) (int, error) {
	state := request.Request{W: writer, Req: msg}
	m := new(dns.Msg)
	m.SetReply(msg)
	m.Authoritative = true
	// 应对0x20
	q := strings.ToLower(state.QName())
	qlist := strings.Split(q, ".")
	// 符合要求的域名
	if len(qlist) >= 4 {
		// 1.入口
		iaddr := strings.ReplaceAll(qlist[len(qlist)-5], "-", ":")
		// 2.出口
		oaddr := state.IP()
		// 3.记录关联
		r.writeData([]string{iaddr, oaddr})
		// 4.返回响应
		m = r.response(m, state)
		err := writer.WriteMsg(m)
		if err != nil {
			log.Info(err.Error())
			return dns.RcodeServerFailure, err
		}
	}
	return 0, nil
}

func (r Rtest) Name() string {
	return "rtest"
}

func (r Rtest) newCSVwriterAndWrite(path string) chan []string {
	f, err := os.OpenFile("./"+time.Now().Format("2006_01_02-15_03_04")+"_"+path, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	if err != nil {
		fmt.Println("Error: ", err)
		return nil
	}

	csvWriter := *csv.NewWriter(f)
	csvWriter.UseCRLF = true
	var header = []string{"from", "to"}
	err = csvWriter.Write(header)
	if err != nil {
		return nil
	}
	csvWriter.Flush()
	datachan := make(chan []string, 10)
	go func() {
		defer func(f *os.File) {
			err = f.Close()
			if err != nil {
				log.Errorf("%v", err.Error())
			}
		}(f)
		for i := range datachan {
			log.Debug(i)
			err = csvWriter.Write(i)
			if err != nil {
				log.Errorf("%v", err.Error())
				return
			}
			csvWriter.Flush()
		}
	}()
	return datachan
}

func (r Rtest) writeData(data []string) {
	r.datachan <- data
}

func (r Rtest) response(msg *dns.Msg, state request.Request) *dns.Msg {
	//返回AAAA记录
	msg.Rcode = dns.RcodeSuccess
	aaaa := new(dns.AAAA)
	aaaa.Hdr = dns.RR_Header{Name: state.QName(), Class: dns.ClassINET, Ttl: 10, Rrtype: dns.TypeAAAA}
	aaaa.AAAA = net.ParseIP(r.addr)
	msg.Answer = append(msg.Answer, aaaa)
	//授权记录
	rec := new(dns.NS)
	rec.Hdr = dns.RR_Header{Name: "rtest.n64.top.", Class: dns.ClassINET, Ttl: 10, Rrtype: dns.TypeNS}
	rec.Ns = r.ns
	msg.Ns = append(msg.Ns, rec)
	//胶水记录
	recaddr := new(dns.AAAA)
	recaddr.Hdr = dns.RR_Header{Name: r.ns, Class: dns.ClassINET, Ttl: 10, Rrtype: dns.TypeAAAA}
	recaddr.AAAA = net.ParseIP(state.LocalIP())
	msg.Extra = append(msg.Extra, recaddr)
	return msg
}
