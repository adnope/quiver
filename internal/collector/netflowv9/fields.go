package netflowv9

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"unicode/utf8"

	decoder "github.com/netsampler/goflow2/v2/decoders/netflow"
)

type decodedTemplate struct {
	id      uint16
	fields  []FieldDefinition
	scopes  []FieldDefinition
	options []FieldDefinition
}

func decodeTemplateFlowSet(payload []byte, maxFields int) ([]decodedTemplate, int, bool, error) {
	consumed := 0
	for len(payload)-consumed > 3 {
		remaining := payload[consumed:]
		if len(remaining) < 4 {
			return nil, 0, false, decodeError("invalid_template", "template record header is truncated")
		}
		templateID := binary.BigEndian.Uint16(remaining[:2])
		fieldCount := int(binary.BigEndian.Uint16(remaining[2:4]))
		if templateID < 256 {
			return nil, 0, false, decodeError("invalid_template", "template id %d is below 256", templateID)
		}
		if fieldCount == 0 || fieldCount > maxFields {
			return nil, 0, false, decodeError("template_limit", "template %d field count %d exceeds limits", templateID, fieldCount)
		}
		recordLength := 4 + fieldCount*4
		if recordLength > len(remaining) {
			return nil, 0, false, decodeError("invalid_template", "template %d fields exceed flowset boundary", templateID)
		}
		consumed += recordLength
	}
	padding := payload[consumed:]
	if len(padding) > 3 {
		return nil, 0, false, decodeError("invalid_padding", "template padding exceeds three bytes")
	}

	records, err := decoder.DecodeTemplateSet(9, bytes.NewBuffer(payload[:consumed]))
	if err != nil {
		return nil, 0, false, decodeError("invalid_template", "decode template set: %v", err)
	}
	decoded := make([]decodedTemplate, 0, len(records))
	for _, record := range records {
		fields := make([]FieldDefinition, 0, len(record.Fields))
		for _, field := range record.Fields {
			fields = append(fields, FieldDefinition{ID: field.Type, Length: field.Length})
		}
		decoded = append(decoded, decodedTemplate{id: record.TemplateId, fields: fields})
	}
	return decoded, len(padding), hasNonZeroByte(padding), nil
}

func decodeOptionsTemplateFlowSet(payload []byte, maxFields int) ([]decodedTemplate, int, bool, error) {
	consumed := 0
	for len(payload)-consumed > 3 {
		remaining := payload[consumed:]
		if len(remaining) < 6 {
			return nil, 0, false, decodeError("invalid_options_template", "options template header is truncated")
		}
		templateID := binary.BigEndian.Uint16(remaining[:2])
		scopeLength := int(binary.BigEndian.Uint16(remaining[2:4]))
		optionLength := int(binary.BigEndian.Uint16(remaining[4:6]))
		if templateID < 256 {
			return nil, 0, false, decodeError("invalid_options_template", "options template id %d is below 256", templateID)
		}
		if scopeLength%4 != 0 || optionLength%4 != 0 {
			return nil, 0, false, decodeError("invalid_options_template", "options template %d lengths are not field aligned", templateID)
		}
		if scopeLength == 0 || optionLength == 0 {
			return nil, 0, false, decodeError("invalid_options_template", "options template %d requires scope and option fields", templateID)
		}
		fieldCount := scopeLength/4 + optionLength/4
		if fieldCount == 0 || fieldCount > maxFields {
			return nil, 0, false, decodeError("template_limit", "options template %d field count %d exceeds limits", templateID, fieldCount)
		}
		recordLength := 6 + scopeLength + optionLength
		if recordLength > len(remaining) {
			return nil, 0, false, decodeError("invalid_options_template", "options template %d fields exceed flowset boundary", templateID)
		}
		consumed += recordLength
	}
	padding := payload[consumed:]

	records, err := decoder.DecodeNFv9OptionsTemplateSet(bytes.NewBuffer(payload[:consumed]))
	if err != nil {
		return nil, 0, false, decodeError("invalid_options_template", "decode options template set: %v", err)
	}
	decoded := make([]decodedTemplate, 0, len(records))
	for _, record := range records {
		scopes := make([]FieldDefinition, 0, len(record.Scopes))
		for _, field := range record.Scopes {
			scopes = append(scopes, FieldDefinition{ID: field.Type, Length: field.Length})
		}
		options := make([]FieldDefinition, 0, len(record.Options))
		for _, field := range record.Options {
			options = append(options, FieldDefinition{ID: field.Type, Length: field.Length})
		}
		decoded = append(decoded, decodedTemplate{id: record.TemplateId, scopes: scopes, options: options})
	}
	return decoded, len(padding), hasNonZeroByte(padding), nil
}

func decodeDataFields(fields []FieldDefinition, payload []byte, isScope bool) ([]DecodedField, error) {
	dependencyFields := make([]decoder.Field, 0, len(fields))
	for _, field := range fields {
		dependencyFields = append(dependencyFields, decoder.Field{Type: field.ID, Length: field.Length})
	}
	values, err := decoder.DecodeDataSetUsingFields(9, bytes.NewBuffer(payload), dependencyFields)
	if err != nil {
		return nil, decodeError("invalid_record", "decode data fields: %v", err)
	}
	if len(values) != len(fields) {
		return nil, decodeError("invalid_record", "decoded field count %d does not match template count %d", len(values), len(fields))
	}

	decoded := make([]DecodedField, 0, len(values))
	for index, value := range values {
		raw, err := dependencyBytes(value.Value)
		if err != nil {
			return nil, err
		}
		field := fields[index]
		if len(raw) != int(field.Length) {
			return nil, decodeError("invalid_field_length", "field %d decoded length %d does not match %d", field.ID, len(raw), field.Length)
		}
		decodedValue, err := decodeFieldValue(field.ID, raw, isScope)
		if err != nil {
			return nil, err
		}
		name := decoder.NFv9TypeToString(field.ID)
		if isScope {
			name = decoder.NFv9ScopeToString(field.ID)
		}
		if name == "Unassigned" {
			name = ""
		}
		decoded = append(decoded, DecodedField{
			ID:     field.ID,
			Length: field.Length,
			Name:   name,
			Value:  decodedValue,
		})
	}
	return decoded, nil
}

func dependencyBytes(value any) ([]byte, error) {
	switch typed := value.(type) {
	case []byte:
		return bytes.Clone(typed), nil
	default:
		return nil, decodeError("unsupported_decoder_value", "decoder returned unsupported value type %T", value)
	}
}

func decodeFieldValue(fieldID uint16, raw []byte, isScope bool) (FieldValue, error) {
	if isIPv4Field(fieldID) && !isScope {
		if len(raw) != 4 {
			return FieldValue{}, decodeError("invalid_field_length", "ipv4 field %d requires four bytes", fieldID)
		}
		address := netip.AddrFrom4([4]byte(raw))
		return FieldValue{Kind: ValueKindString, String: address.String()}, nil
	}
	if isIPv6Field(fieldID) && !isScope {
		if len(raw) != 16 {
			return FieldValue{}, decodeError("invalid_field_length", "ipv6 field %d requires sixteen bytes", fieldID)
		}
		var addressBytes [16]byte
		copy(addressBytes[:], raw)
		return FieldValue{Kind: ValueKindString, String: netip.AddrFrom16(addressBytes).String()}, nil
	}
	if isStringField(fieldID) && !isScope {
		value := strings.TrimRight(string(raw), "\x00")
		if !utf8.ValidString(value) {
			return FieldValue{}, decodeError("invalid_string", "field %d is not valid utf-8", fieldID)
		}
		return FieldValue{Kind: ValueKindString, String: value}, nil
	}
	if isScope || isStandardNumericField(fieldID) {
		if len(raw) == 0 || len(raw) > 8 {
			return FieldValue{}, decodeError("invalid_field_length", "numeric field %d length must be within 1..8", fieldID)
		}
		var value uint64
		for _, item := range raw {
			value = value<<8 | uint64(item)
		}
		return FieldValue{Kind: ValueKindUnsigned, Unsigned: value}, nil
	}
	return FieldValue{Kind: ValueKindBytes, Bytes: bytes.Clone(raw)}, nil
}

func recordWidth(fields []FieldDefinition, maxRecordBytes int) (int, error) {
	width := 0
	for _, field := range fields {
		if field.Length == 0 || field.Length == 0xffff {
			return 0, decodeError("invalid_field_length", "field %d has unsupported length %d", field.ID, field.Length)
		}
		if int(field.Length) > maxRecordBytes-width {
			return 0, decodeError("record_limit", "template record exceeds %d bytes", maxRecordBytes)
		}
		width += int(field.Length)
	}
	if width == 0 {
		return 0, decodeError("invalid_template", "template has zero record width")
	}
	return width, nil
}

func hasNonZeroByte(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return true
		}
	}
	return false
}

func isIPv4Field(fieldID uint16) bool {
	switch fieldID {
	case 8, 12, 15, 18, 44, 45, 47:
		return true
	default:
		return false
	}
}

func isIPv6Field(fieldID uint16) bool {
	switch fieldID {
	case 27, 28, 62, 63:
		return true
	default:
		return false
	}
}

func isStringField(fieldID uint16) bool {
	switch fieldID {
	case 82, 83, 84, 94, 95, 96:
		return true
	default:
		return false
	}
}

func isStandardNumericField(fieldID uint16) bool {
	return (fieldID >= 1 && fieldID <= 104) || fieldID == 234 || fieldID == 235
}

func templateSignature(kind TemplateKind, fields []FieldDefinition, scopes []FieldDefinition, options []FieldDefinition) string {
	var builder strings.Builder
	_, _ = fmt.Fprintf(&builder, "%d|", kind)
	for _, group := range [][]FieldDefinition{fields, scopes, options} {
		for _, field := range group {
			_, _ = fmt.Fprintf(&builder, "%d:%d,", field.ID, field.Length)
		}
		builder.WriteByte('|')
	}
	return builder.String()
}
