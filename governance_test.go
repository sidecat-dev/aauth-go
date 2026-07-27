package aauth

import "testing"

func TestPermissionAndAuditRequestValidation(t *testing.T) {
	t.Parallel()

	validMission := MissionReference{
		Approver: "https://ps.example",
		S256:     S256([]byte("mission")),
	}
	for name, test := range map[string]struct {
		request PermissionRequest
		valid   bool
	}{
		"action": {
			request: PermissionRequest{Action: "filesystem.read"},
			valid:   true,
		},
		"mission": {
			request: PermissionRequest{
				Action:  "filesystem.write",
				Mission: &validMission,
			},
			valid: true,
		},
		"missing action": {
			request: PermissionRequest{},
		},
		"invalid mission": {
			request: PermissionRequest{
				Action:  "filesystem.write",
				Mission: &MissionReference{},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := test.request.Validate()
			if test.valid && err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if !test.valid && err == nil {
				t.Fatal("Validate accepted an invalid permission request")
			}
		})
	}

	if err := (AuditRequest{
		Mission: validMission,
		Action:  "filesystem.write",
	}).Validate(); err != nil {
		t.Fatalf("valid audit request: %v", err)
	}
	if err := (AuditRequest{Action: "filesystem.write"}).Validate(); err == nil {
		t.Fatal("audit request without a mission was accepted")
	}
	if err := (AuditRequest{Mission: validMission}).Validate(); err == nil {
		t.Fatal("audit request without an action was accepted")
	}
}

func TestPermissionResponseValidation(t *testing.T) {
	t.Parallel()

	for name, test := range map[string]struct {
		response PermissionResponse
		valid    bool
	}{
		"granted": {
			response: PermissionResponse{Permission: PermissionGranted},
			valid:    true,
		},
		"denied": {
			response: PermissionResponse{
				Permission: PermissionDenied,
				Reason:     "operator declined",
			},
			valid: true,
		},
		"unknown": {
			response: PermissionResponse{Permission: "maybe"},
		},
		"grant with denial reason": {
			response: PermissionResponse{
				Permission: PermissionGranted,
				Reason:     "contradictory",
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := test.response.Validate()
			if test.valid && err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if !test.valid && err == nil {
				t.Fatal("Validate accepted an invalid permission response")
			}
		})
	}
}
