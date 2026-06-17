package zeek

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/adnope/quiver/internal/domain"
	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

var ErrInvalidLine = errors.New("zeek: invalid conn json line")

func ParseConnLine(line []byte) (*flowv1.ZeekConnFlow, error) {
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.UseNumber()
	fields := map[string]any{}
	if err := decoder.Decode(&fields); err != nil {
		return nil, fmt.Errorf("%w: decode json: %v", ErrInvalidLine, err)
	}
	flow := &flowv1.ZeekConnFlow{}
	extra := map[string]any{}
	for key, value := range fields {
		switch key {
		case "ts":
			parsed, err := float64Field(value, key)
			if err != nil {
				return nil, err
			}
			flow.Ts = parsed
		case "uid":
			flow.Uid = stringField(value)
		case "id.orig_h":
			flow.IdOrigH = stringField(value)
		case "id.orig_p":
			parsed, ok, err := optionalUint32Field(value, key)
			if err != nil {
				return nil, err
			}
			if ok {
				flow.IdOrigP = &parsed
			}
		case "id.resp_h":
			flow.IdRespH = stringField(value)
		case "id.resp_p":
			parsed, ok, err := optionalUint32Field(value, key)
			if err != nil {
				return nil, err
			}
			if ok {
				flow.IdRespP = &parsed
			}
		case "proto":
			flow.Proto = stringField(value)
		case "service":
			setString(&flow.Service, value)
		case "duration":
			if err := setFloat64(&flow.Duration, value, key); err != nil {
				return nil, err
			}
		case "orig_bytes":
			if err := setUint64(&flow.OrigBytes, value, key); err != nil {
				return nil, err
			}
		case "resp_bytes":
			if err := setUint64(&flow.RespBytes, value, key); err != nil {
				return nil, err
			}
		case "orig_pkts":
			if err := setUint64(&flow.OrigPkts, value, key); err != nil {
				return nil, err
			}
		case "resp_pkts":
			if err := setUint64(&flow.RespPkts, value, key); err != nil {
				return nil, err
			}
		case "conn_state":
			setString(&flow.ConnState, value)
		case "history":
			setString(&flow.History, value)
		case "local_orig":
			setBool(&flow.LocalOrig, value)
		case "local_resp":
			setBool(&flow.LocalResp, value)
		case "missed_bytes":
			if err := setUint64(&flow.MissedBytes, value, key); err != nil {
				return nil, err
			}
		default:
			if domain.IsSensitiveKey(key) {
				extra[key] = "***MASKED***"
			} else {
				extra[key] = value
			}
		}
	}
	if flow.Ts <= 0 || strings.TrimSpace(flow.IdOrigH) == "" ||
		strings.TrimSpace(flow.IdRespH) == "" || strings.TrimSpace(flow.Proto) == "" {
		return nil, fmt.Errorf("%w: required conn fields are missing", ErrInvalidLine)
	}
	if len(extra) > 0 {
		value, err := structpb.NewStruct(extra)
		if err != nil {
			return nil, fmt.Errorf("%w: extra fields: %v", ErrInvalidLine, err)
		}
		flow.Extra = value
	}
	return flow, nil
}

func stringField(value any) string {
	text, _ := value.(string)
	if text == "-" {
		return ""
	}
	return text
}

func setString(target **string, value any) {
	text := stringField(value)
	if text != "" {
		*target = &text
	}
}

func setBool(target **bool, value any) {
	parsed, ok := value.(bool)
	if ok {
		*target = &parsed
	}
}

func setFloat64(target **float64, value any, field string) error {
	parsed, err := float64Field(value, field)
	if err == nil {
		*target = &parsed
	}
	return err
}

func setUint64(target **uint64, value any, field string) error {
	parsed, ok, err := optionalUint64Field(value, field)
	if err == nil && ok {
		*target = &parsed
	}
	return err
}

func float64Field(value any, field string) (float64, error) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, fmt.Errorf("%w: %s must be numeric", ErrInvalidLine, field)
	}
	parsed, err := number.Float64()
	if err != nil {
		return 0, fmt.Errorf("%w: %s must be numeric", ErrInvalidLine, field)
	}
	return parsed, nil
}

func optionalUint32Field(value any, field string) (uint32, bool, error) {
	parsed, ok, err := optionalUint64Field(value, field)
	if err != nil || !ok {
		return 0, ok, err
	}
	if parsed > uint64(^uint32(0)) {
		return 0, false, fmt.Errorf("%w: %s out of range", ErrInvalidLine, field)
	}
	return uint32(parsed), true, nil
}

func optionalUint64Field(value any, field string) (uint64, bool, error) {
	if value == nil {
		return 0, false, nil
	}
	if text, ok := value.(string); ok && text == "-" {
		return 0, false, nil
	}
	number, ok := value.(json.Number)
	if !ok {
		return 0, false, fmt.Errorf("%w: %s must be numeric", ErrInvalidLine, field)
	}
	parsed, err := number.Int64()
	if err != nil || parsed < 0 {
		return 0, false, fmt.Errorf("%w: %s must be unsigned integer", ErrInvalidLine, field)
	}
	return uint64(parsed), true, nil
}
