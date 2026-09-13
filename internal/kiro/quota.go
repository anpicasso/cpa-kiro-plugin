package kiro

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/xiaokui-dev/cliproxyapi-kiro-plugin/internal/wire"
)

// quotaFetchRequest mirrors CPA's quota.fetch request. StorageJSON is decoded
// by encoding/json from the host's base64 []byte representation.
type quotaFetchRequest struct {
	AuthIndex      string `json:"auth_index"`
	Provider       string `json:"provider"`
	StorageJSON    []byte `json:"storage_json,omitempty"`
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

type quotaDescribeResponse struct {
	SupportedProviders []string `json:"supported_providers,omitempty"`
	DisplayName        string   `json:"display_name,omitempty"`
	SupportsReset      bool     `json:"supports_reset,omitempty"`
}

type quotaSubscription struct {
	Plan     string `json:"plan,omitempty"`
	TierName string `json:"tierName,omitempty"`
	TierID   string `json:"tierId,omitempty"`
}

type quotaBucket struct {
	Window            string  `json:"window,omitempty"`
	RemainingFraction float64 `json:"remainingFraction"`
	ResetTime         string  `json:"resetTime,omitempty"`
	Description       string  `json:"description,omitempty"`
}

type quotaGroup struct {
	DisplayName string        `json:"displayName,omitempty"`
	Buckets     []quotaBucket `json:"buckets,omitempty"`
}

type quotaFetchResponse struct {
	Subscription *quotaSubscription `json:"subscription,omitempty"`
	Groups       []quotaGroup       `json:"groups,omitempty"`
}

type quotaResetResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

type kiroUsageLimits struct {
	NextDateReset    float64 `json:"nextDateReset"`
	SubscriptionInfo struct {
		SubscriptionTitle string `json:"subscriptionTitle"`
		Type              string `json:"type"`
	} `json:"subscriptionInfo"`
	UsageBreakdownList []kiroUsageBreakdown `json:"usageBreakdownList"`
}

type kiroUsageBreakdown struct {
	DisplayName                  string   `json:"displayName"`
	ResourceType                 string   `json:"resourceType"`
	Unit                         string   `json:"unit"`
	CurrentUsage                 float64  `json:"currentUsage"`
	CurrentUsageWithPrecision    *float64 `json:"currentUsageWithPrecision"`
	UsageLimit                   float64  `json:"usageLimit"`
	UsageLimitWithPrecision      *float64 `json:"usageLimitWithPrecision"`
	CurrentOverages              float64  `json:"currentOverages"`
	CurrentOveragesWithPrecision *float64 `json:"currentOveragesWithPrecision"`
	OverageCharges               float64  `json:"overageCharges"`
	OverageRate                  float64  `json:"overageRate"`
	Currency                     string   `json:"currency"`
	NextDateReset                float64  `json:"nextDateReset"`
}

func fetchKiroQuota(request []byte) ([]byte, error) {
	var req quotaFetchRequest
	if err := json.Unmarshal(request, &req); err != nil {
		return nil, err
	}
	if provider := strings.TrimSpace(req.Provider); provider != "" && !strings.EqualFold(provider, providerKiro) {
		return wire.Error("invalid_credential", "quota request is not for Kiro"), nil
	}
	var cred kiroCredential
	if err := json.Unmarshal(req.StorageJSON, &cred); err != nil {
		return wire.ErrorStatus("invalid_credential", "decode kiro credential: "+err.Error(), http.StatusBadRequest), nil
	}
	if strings.TrimSpace(cred.AccessToken) == "" {
		return wire.ErrorStatus("invalid_credential", "kiro credential has no accessToken", http.StatusUnauthorized), nil
	}

	raw, err := fetchUsageLimits(req.HostCallbackID, cred)
	if err != nil {
		return wire.Error("quota_fetch_failed", err.Error()), nil
	}
	resp, err := normalizeKiroQuota(raw)
	if err != nil {
		return wire.Error("quota_fetch_failed", "decode Kiro usage response: "+err.Error()), nil
	}
	return wire.OK(resp)
}

func normalizeKiroQuota(raw []byte) (quotaFetchResponse, error) {
	var usage kiroUsageLimits
	if err := json.Unmarshal(raw, &usage); err != nil {
		return quotaFetchResponse{}, err
	}

	resp := quotaFetchResponse{Subscription: &quotaSubscription{
		Plan:     usage.SubscriptionInfo.SubscriptionTitle,
		TierName: usage.SubscriptionInfo.SubscriptionTitle,
		TierID:   usage.SubscriptionInfo.Type,
	}}
	if resp.Subscription.Plan == "" && resp.Subscription.TierID == "" {
		resp.Subscription = nil
	}

	group := quotaGroup{DisplayName: "Kiro credits"}
	for _, item := range usage.UsageBreakdownList {
		used := precise(item.CurrentUsage, item.CurrentUsageWithPrecision)
		limit := precise(item.UsageLimit, item.UsageLimitWithPrecision)
		overage := precise(item.CurrentOverages, item.CurrentOveragesWithPrecision)
		remaining := 0.0
		if limit > 0 {
			remaining = math.Max(0, math.Min(1, (limit-used)/limit))
		}
		reset := item.NextDateReset
		if reset == 0 {
			reset = usage.NextDateReset
		}
		label := strings.TrimSpace(item.DisplayName)
		if label == "" {
			label = strings.TrimSpace(item.ResourceType)
		}
		if label == "" {
			label = "Credits"
		}
		unit := strings.TrimSpace(item.Unit)
		description := fmt.Sprintf("%s: %.2f / %.2f %s", label, used, limit, unit)
		if overage > 0 {
			description += fmt.Sprintf(" · %.2f overage", overage)
		}
		if item.OverageCharges > 0 {
			description += fmt.Sprintf(" · %s %.2f charged", strings.TrimSpace(item.Currency), item.OverageCharges)
		}
		if item.OverageRate > 0 {
			description += fmt.Sprintf(" · %s %.2f/%s", strings.TrimSpace(item.Currency), item.OverageRate, unit)
		}
		group.Buckets = append(group.Buckets, quotaBucket{
			Window:            "credits",
			RemainingFraction: remaining,
			ResetTime:         quotaResetTime(reset),
			Description:       description,
		})
	}
	if len(group.Buckets) > 0 {
		resp.Groups = []quotaGroup{group}
	}
	return resp, nil
}

func precise(fallback float64, precise *float64) float64 {
	if precise != nil {
		return *precise
	}
	return fallback
}

func quotaResetTime(epochSeconds float64) string {
	if epochSeconds <= 0 {
		return ""
	}
	return time.Unix(int64(epochSeconds), 0).UTC().Format(time.RFC3339)
}
