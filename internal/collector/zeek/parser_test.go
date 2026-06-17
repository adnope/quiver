package zeek

import (
	"errors"
	"testing"
)

func TestParseConnLineMapsDottedFields(t *testing.T) {
	t.Parallel()

	line := []byte(`{"ts":1718532920.125,"uid":"C1","id.orig_h":"192.0.2.10","id.orig_p":51524,"id.resp_h":"198.51.100.20","id.resp_p":443,"proto":"tcp","service":"ssl","duration":1.5,"orig_bytes":120,"resp_bytes":340,"orig_pkts":2,"resp_pkts":3,"conn_state":"SF","history":"ShAD","local_orig":true,"local_resp":false,"missed_bytes":0,"note":"ok","api_token":"secret"}`)
	flow, err := ParseConnLine(line)
	if err != nil {
		t.Fatalf("ParseConnLine() error = %v", err)
	}
	if flow.GetUid() != "C1" || flow.GetIdOrigH() != "192.0.2.10" || flow.GetIdRespH() != "198.51.100.20" {
		t.Fatalf("identity fields not mapped: %+v", flow)
	}
	if flow.GetIdOrigP() != 51524 || flow.GetIdRespP() != 443 {
		t.Fatalf("ports = %d/%d", flow.GetIdOrigP(), flow.GetIdRespP())
	}
	if flow.GetService() != "ssl" || flow.GetDuration() != 1.5 || flow.GetOrigBytes() != 120 || flow.GetRespPkts() != 3 {
		t.Fatalf("optional fields not mapped: %+v", flow)
	}
	if flow.GetExtra().GetFields()["api_token"].GetStringValue() != "***MASKED***" {
		t.Fatalf("sensitive extra field was not masked: %v", flow.GetExtra())
	}
}

func TestParseConnLineRejectsMalformedOptionalNumeric(t *testing.T) {
	t.Parallel()

	_, err := ParseConnLine([]byte(`{"ts":1718532920.125,"uid":"C1","id.orig_h":"192.0.2.10","id.resp_h":"198.51.100.20","proto":"tcp","orig_bytes":"bad"}`))
	if !errors.Is(err, ErrInvalidLine) {
		t.Fatalf("ParseConnLine() error = %v, want ErrInvalidLine", err)
	}
}

func TestParseConnLineTreatsDashAsMissing(t *testing.T) {
	t.Parallel()

	flow, err := ParseConnLine([]byte(`{"ts":1718532920.125,"uid":"C1","id.orig_h":"192.0.2.10","id.orig_p":"-","id.resp_h":"198.51.100.20","id.resp_p":"-","proto":"tcp","service":"-"}`))
	if err != nil {
		t.Fatalf("ParseConnLine() error = %v", err)
	}
	if flow.IdOrigP != nil || flow.IdRespP != nil || flow.Service != nil {
		t.Fatalf("dash fields should be omitted: %+v", flow)
	}
}
