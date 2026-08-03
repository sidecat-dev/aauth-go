package reference

import "testing"

func TestClassifyR3ProposalReferenceRefusesDigestPathMismatch(t *testing.T) {
	t.Parallel()

	proposal, err := classifyR3ProposalReference(
		"https://resource.example",
		"https://resource.example/r3/proposals/other-digest",
		"approved-digest",
	)
	if err == nil {
		t.Fatal("mismatched proposal digest path was accepted")
	}
	if proposal {
		t.Fatal("mismatched proposal digest path was classified as usable")
	}
}

func TestClassifyR3ProposalReferenceDistinguishesExactProposalAndClass(t *testing.T) {
	t.Parallel()

	proposal, err := classifyR3ProposalReference(
		"https://resource.example",
		"https://resource.example/r3/proposals/approved-digest",
		"approved-digest",
	)
	if err != nil || !proposal {
		t.Fatalf("exact proposal classification = %t, %v", proposal, err)
	}

	proposal, err = classifyR3ProposalReference(
		"https://resource.example",
		"https://resource.example/r3/class-digest",
		"class-digest",
	)
	if err != nil || proposal {
		t.Fatalf("class-document classification = %t, %v", proposal, err)
	}
}
