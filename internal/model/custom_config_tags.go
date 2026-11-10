package model

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type outboundTagSource struct {
	Tag    string
	Source string
}

func collectAdditionalOutboundTagSources(customConfig map[string]any, rawOutbounds []map[string]any) []outboundTagSource {
	sources := collectRawOutboundTagSources(rawOutbounds)
	return append(sources, collectCustomConfigOutboundTagSources(customConfig)...)
}

func collectRawOutboundTagSources(outbounds []map[string]any) []outboundTagSource {
	if len(outbounds) == 0 {
		return nil
	}
	sources := make([]outboundTagSource, 0, len(outbounds))
	for i, outbound := range outbounds {
		tag, _ := outbound["tag"].(string)
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		sources = append(sources, outboundTagSource{Tag: tag, Source: fmt.Sprintf("kernel.custom_outbound[%d]", i)})
	}
	return sources
}

// decodeCustomConfig reads a kernel-native custom config file. It returns nil
// when the path is empty, the file is missing, or the file is empty.
func decodeCustomConfig(path string) (map[string]any, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read custom config %q: %w", path, err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, nil
	}

	decoded := make(map[string]any)
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "{") {
		if err := json.Unmarshal(data, &decoded); err != nil {
			return nil, fmt.Errorf("parse custom config as JSON: %w", err)
		}
	} else {
		if err := yaml.Unmarshal(data, &decoded); err != nil {
			return nil, fmt.Errorf("parse custom config as YAML: %w", err)
		}
	}
	return decoded, nil
}

// Keys specific to each kernel's native format, in lower case. Matching is
// case-insensitive because Xray's JSON decoder is.
var (
	singboxOnlyCustomConfigKeys = []string{"route", "experimental", "endpoints", "ntp", "certificate", "certificate_providers", "http_clients", "network_namespaces", "services"}
	xrayOnlyCustomConfigKeys    = []string{"routing", "policy", "api", "stats", "transport", "reverse", "fakedns", "observatory", "burstobservatory", "metrics"}
	singboxOnlyDNSKeys          = []string{"rules", "final", "reverse_mapping", "strategy", "timeout", "disable_cache", "disable_expire", "independent_cache", "cache_capacity", "optimistic", "client_subnet"}
	xrayOnlyDNSKeys             = []string{"script", "hosts", "clientip", "tag", "querystrategy", "disablecache", "servestale", "serveexpiredttl", "disablefallback", "disablefallbackifmatch", "enableparallelquery", "usesystemhosts"}
)

// LoadCustomConfigForKernel reads kernel.custom_config and rejects keys
// specific to the other kernel. Auto kernel selection may run a node on a
// kernel other than the configured one, and a native config only applies to
// its own kernel. The result is never nil: an empty map means there is no
// file, so kernels can tell "loaded nothing" from "not loaded".
func LoadCustomConfigForKernel(path, kernelType string) (map[string]any, error) {
	decoded, err := decodeCustomConfig(path)
	if err != nil {
		return nil, err
	}
	if err := validateCustomConfigKernel(path, decoded, kernelType); err != nil {
		return nil, err
	}
	if decoded == nil {
		decoded = map[string]any{}
	}
	return decoded, nil
}

func validateCustomConfigKernel(path string, decoded map[string]any, kernelType string) error {
	if decoded == nil {
		return nil
	}
	var foreign, foreignDNS []string
	var other string
	switch kernelType {
	case "xray":
		foreign, foreignDNS, other = singboxOnlyCustomConfigKeys, singboxOnlyDNSKeys, "sing-box"
	case "singbox":
		foreign, foreignDNS, other = xrayOnlyCustomConfigKeys, xrayOnlyDNSKeys, "xray"
	default:
		return nil
	}
	present := foreignKeys(decoded, foreign, "")
	for key, value := range decoded {
		if strings.EqualFold(key, "dns") {
			dns, _ := value.(map[string]any)
			present = append(present, foreignKeys(dns, foreignDNS, key+".")...)
		}
	}
	if len(present) == 0 {
		return nil
	}
	sort.Strings(present)
	return fmt.Errorf("kernel.custom_config %q contains %s-only keys %v; use a %s-native custom config for this node",
		path, other, present, kernelType)
}

func foreignKeys(config map[string]any, markers []string, prefix string) []string {
	var present []string
	for key := range config {
		if slices.Contains(markers, strings.ToLower(key)) {
			present = append(present, prefix+key)
		}
	}
	return present
}

func collectCustomConfigOutboundTagSources(decoded map[string]any) []outboundTagSource {
	if decoded == nil {
		return nil
	}
	items, ok := toSliceOfMaps(decoded["outbounds"])
	if !ok {
		return nil
	}
	sources := make([]outboundTagSource, 0, len(items))
	for i, item := range items {
		tag, _ := item["tag"].(string)
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		sources = append(sources, outboundTagSource{Tag: tag, Source: fmt.Sprintf("kernel.custom_config.outbounds[%d]", i)})
	}
	return sources
}

func toSliceOfMaps(v any) ([]map[string]any, bool) {
	if v == nil {
		return nil, false
	}
	switch items := v.(type) {
	case []any:
		result := make([]map[string]any, 0, len(items))
		for _, item := range items {
			mapped, ok := toMap(item)
			if ok {
				result = append(result, mapped)
			}
		}
		return result, len(result) > 0
	case []map[string]any:
		return items, len(items) > 0
	default:
		return nil, false
	}
}

func toMap(v any) (map[string]any, bool) {
	switch mapped := v.(type) {
	case map[string]any:
		return mapped, true
	case map[any]any:
		result := make(map[string]any, len(mapped))
		for k, val := range mapped {
			result[fmt.Sprint(k)] = val
		}
		return result, true
	default:
		return nil, false
	}
}

func validateOutboundTagCollisions(structured []OutboundConfig, additional []outboundTagSource) error {
	seen := make(map[string]string, len(additional))
	for _, source := range additional {
		key := strings.ToLower(strings.TrimSpace(source.Tag))
		if key == "" {
			continue
		}
		if prev, exists := seen[key]; exists {
			return fmt.Errorf("%s.tag duplicates %q from %s", source.Source, source.Tag, prev)
		}
		seen[key] = source.Source
	}
	for i, outbound := range structured {
		key := strings.ToLower(strings.TrimSpace(outbound.Tag))
		if key == "" {
			continue
		}
		if prev, exists := seen[key]; exists {
			return fmt.Errorf("custom_outbounds[%d].tag duplicates %q from %s", i, outbound.Tag, prev)
		}
	}
	return nil
}

func additionalTagNames(sources []outboundTagSource) []string {
	if len(sources) == 0 {
		return nil
	}
	tags := make([]string, 0, len(sources))
	for _, source := range sources {
		tags = append(tags, source.Tag)
	}
	return tags
}
