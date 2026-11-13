package model

import (
	"fmt"
	"strings"

	"github.com/cedar2025/xboard-node/internal/config"
)

func ValidateNodeSpec(n *NodeSpec, kcfg config.KernelConfig) error {
	if n == nil {
		return nil
	}

	if n.Protocol == "snell" {
		if n.PSKMode != "" && n.PSKMode != "shared" && n.PSKMode != "user" {
			return fmt.Errorf("unknown Snell psk_mode")
		}
		if n.PSKMode == "user" && n.ShadowTLSServer != "" && n.ShadowTLSPassword == "" {
			return fmt.Errorf("ShadowTLS password is required for independent Snell PSKs")
		}
		if n.PSKMode == "user" && n.Mode == "unsafe-raw" {
			return fmt.Errorf("Snell independent PSKs require an encrypted mode")
		}
	}
	effectiveKernelType := strings.TrimSpace(kcfg.Type)
	if effectiveKernelType == "" {
		effectiveKernelType = strings.TrimSpace(n.KernelType)
	}
	kernelType, err := normalizeKernelType(effectiveKernelType)
	if err != nil {
		return fmt.Errorf("normalize kernel type: %w", err)
	}

	customConfig := kcfg.CustomConfigData
	if customConfig == nil {
		customConfig, err = decodeCustomConfig(kcfg.CustomConfig)
		if err != nil {
			return fmt.Errorf("collect additional outbound tags: %w", err)
		}
	}
	if err := validateCustomConfigKernel(kcfg.CustomConfig, customConfig, kernelType); err != nil {
		return err
	}
	additionalOutboundSources := collectAdditionalOutboundTagSources(customConfig, kcfg.CustomOutbound)
	if err := validateOutboundTagCollisions(n.CustomOutbounds, additionalOutboundSources); err != nil {
		return fmt.Errorf("validate outbound tags: %w", err)
	}
	additionalTags := additionalTagNames(additionalOutboundSources)
	availableTags := buildAvailableOutboundTags(n.CustomOutbounds, additionalTags)
	if err := ValidateCustomOutboundsForKernel(n.CustomOutbounds, kernelType, additionalTags); err != nil {
		return fmt.Errorf("validate custom outbounds: %w", err)
	}
	if err := ValidateCustomRouteRules(n.CustomRouteRules, kernelType, availableTags); err != nil {
		return fmt.Errorf("validate custom route rules: %w", err)
	}
	if err := validateTransportKernel(n.Network, kernelType); err != nil {
		return err
	}
	return nil
}

// singboxUnsupportedTransports lists transport types that sing-box does not support.
var singboxUnsupportedTransports = map[string]bool{
	"xhttp":     true,
	"splithttp": true,
}

func validateTransportKernel(network, kernelType string) error {
	net := strings.ToLower(strings.TrimSpace(network))
	if kernelType == "singbox" && singboxUnsupportedTransports[net] {
		return fmt.Errorf("transport %q is not supported by sing-box kernel; use xray kernel instead", net)
	}
	return nil
}

// ResolveKernelForNode applies the panel node's protocol and transport policy
// without changing the configured preference for other nodes.
func ResolveKernelForNode(n *NodeSpec, configuredKernel string) string {
	if n == nil {
		return configuredKernel
	}
	if normalized, err := normalizeKernelType(configuredKernel); err == nil {
		configuredKernel = normalized
	}
	// Hysteria v2 is policy; v1 has no Xray inbound at all.
	if configuredKernel == "xray" && (n.Protocol == "hysteria2" || n.Protocol == "hysteria") {
		return "singbox"
	}
	// Xray has no Snell inbound.
	if configuredKernel == "xray" && n.Protocol == "snell" {
		return "singbox"
	}
	net := strings.ToLower(strings.TrimSpace(n.Network))
	if configuredKernel == "singbox" && singboxUnsupportedTransports[net] {
		return "xray"
	}
	return configuredKernel
}

func normalizeKernelType(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "singbox", "sing-box":
		return "singbox", nil
	case "xray":
		return "xray", nil
	default:
		return "", fmt.Errorf("unsupported kernel type %q", value)
	}
}

func buildAvailableOutboundTags(structured []OutboundConfig, rawTags []string) map[string]struct{} {
	available := map[string]struct{}{
		"direct": {},
		"block":  {},
	}
	for _, outbound := range structured {
		tag := strings.ToLower(strings.TrimSpace(outbound.Tag))
		if tag != "" {
			available[tag] = struct{}{}
		}
	}
	for _, tag := range rawTags {
		tag = strings.ToLower(strings.TrimSpace(tag))
		if tag != "" {
			available[tag] = struct{}{}
		}
	}
	return available
}
