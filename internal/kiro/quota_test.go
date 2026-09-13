package kiro

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/xiaokui-dev/cliproxyapi-kiro-plugin/internal/hostapi"
	"github.com/xiaokui-dev/cliproxyapi-kiro-plugin/internal/wire"
)

func TestFetchKiroQuotaNormalizesUsage(t *testing.T) {
	oldHTTPDo := kiroHTTPDo
	t.Cleanup(func() { kiroHTTPDo = oldHTTPDo })
	kiroHTTPDo = func(req hostapi.HTTPRequest) (*hostapi.HTTPResponse, error) {
		if req.HostCallbackID != "callback-1" {
			t.Fatalf("callback ID = %q", req.HostCallbackID)
		}
		if !strings.Contains(req.URL, "/getUsageLimits") {
			t.Fatalf("unexpected usage URL: %s", req.URL)
		}
		return &hostapi.HTTPResponse{StatusCode: 200, Body: []byte(`{
			"nextDateReset": 1790812800,
			"subscriptionInfo": {"subscriptionTitle":"KIRO PRO","type":"Q_DEVELOPER_STANDALONE_PRO"},
			"usageBreakdownList": [{
				"displayName":"Credits", "resourceType":"CREDIT", "unit":"INVOCATIONS",
				"currentUsage":1740, "currentUsageWithPrecision":1740.28,
				"usageLimit":1000, "usageLimitWithPrecision":1000,
				"currentOverages":740, "currentOveragesWithPrecision":740.28,
				"overageCharges":29.611456, "overageRate":0.04, "currency":"USD"
			}]
		}`)}, nil
	}

	request, err := json.Marshal(quotaFetchRequest{
		Provider:       providerKiro,
		StorageJSON:    []byte(`{"accessToken":"token","region":"us-east-1"}`),
		HostCallbackID: "callback-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := fetchKiroQuota(request)
	if err != nil {
		t.Fatal(err)
	}
	var envelope wire.Envelope
	if err := json.Unmarshal(raw, &envelope); err != nil || !envelope.OK {
		t.Fatalf("bad envelope: %v %#v", err, envelope.Error)
	}
	var got quotaFetchResponse
	if err := json.Unmarshal(envelope.Result, &got); err != nil {
		t.Fatal(err)
	}
	if got.Subscription == nil || got.Subscription.Plan != "KIRO PRO" {
		t.Fatalf("subscription = %#v", got.Subscription)
	}
	if len(got.Groups) != 1 || len(got.Groups[0].Buckets) != 1 {
		t.Fatalf("groups = %#v", got.Groups)
	}
	bucket := got.Groups[0].Buckets[0]
	if bucket.RemainingFraction != 0 {
		t.Fatalf("remaining fraction = %v, want 0", bucket.RemainingFraction)
	}
	if !strings.Contains(bucket.Description, "740.28 overage") || !strings.Contains(bucket.Description, "USD 29.61 charged") {
		t.Fatalf("description = %q", bucket.Description)
	}
	if bucket.ResetTime != "2026-10-01T00:00:00Z" {
		t.Fatalf("reset time = %q", bucket.ResetTime)
	}
}

func TestKiroQuotaRejectsOtherProvider(t *testing.T) {
	request, err := json.Marshal(quotaFetchRequest{Provider: "other"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := fetchKiroQuota(request)
	if err != nil {
		t.Fatal(err)
	}
	var envelope wire.Envelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.OK || envelope.Error == nil || envelope.Error.Code != "invalid_credential" {
		t.Fatalf("expected invalid_credential, got %#v", envelope)
	}
}
