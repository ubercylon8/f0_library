//go:build windows

package cyberhygiene

import "testing"

func TestParseWindowsServices(t *testing.T) {
	one, err := parseWindowsServices(`{"Name":"SentinelAgent","State":"Running","StartMode":"Auto"}`)
	if err != nil || one["sentinelagent"].State != "Running" {
		t.Fatalf("single service: %+v, %v", one, err)
	}
	many, err := parseWindowsServices(`[{"Name":"Sophos Agent","State":"Running"},{"Name":"SentinelAgent","State":"Stopped"}]`)
	if err != nil || len(many) != 2 || many["sophos agent"].State != "Running" {
		t.Fatalf("service list: %+v, %v", many, err)
	}
	empty, err := parseWindowsServices("")
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty response: %+v, %v", empty, err)
	}
}
