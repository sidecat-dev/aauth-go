package aauth_test

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

const linkedResourceMetadata = "https://api.example/.well-known/aauth-resource.json"

// Resource Metadata Link Relation: the target must be a server identifier
// followed by /.well-known/aauth-resource.json, and an Agent must not fetch a
// target of any other form.
func TestResourceLinkTargetsHaveOneAdmissibleForm(t *testing.T) {
	t.Parallel()

	link, err := aauth.ParseResourceLinkTarget(linkedResourceMetadata)
	if err != nil || link.Issuer != "https://api.example" || link.Target != linkedResourceMetadata {
		t.Fatalf("admissible target = %#v, %v", link, err)
	}
	for _, target := range []string{
		"/.well-known/aauth-resource.json",
		"http://api.example/.well-known/aauth-resource.json",
		"https://api.example/metadata",
		"https://api.example/extra/.well-known/aauth-resource.json",
		"https://api.example/.well-known/aauth-resource.json?x=1",
		"https://api.example/.well-known/aauth-resource.json#top",
		"https://user:pw@api.example/.well-known/aauth-resource.json",
		"https://api.example:8443/.well-known/aauth-resource.json",
		"https://API.example/.well-known/aauth-resource.json",
		"https://api.example/.well-known/aauth-person.json",
		"https://192.0.2.1/.well-known/aauth-resource.json",
	} {
		if link, err := aauth.ParseResourceLinkTarget(target); err == nil {
			t.Errorf("target %q admitted as %#v", target, link)
		}
	}
}

func TestResourceLinksAreReadFromHeadersAndHTML(t *testing.T) {
	t.Parallel()

	header := http.Header{}
	if err := aauth.AddResourceLinks(header, "https://api.example", "https://billing.example"); err != nil {
		t.Fatal(err)
	}
	header.Add("Link", `<https://evil.example/steal>; rel="aauth-resource", `+
		`<https://other.example/.well-known/aauth-resource.json>; rel="other", `+
		`<https://docs.example/.well-known/aauth-resource.json>; rel="preload aauth-resource"; title="a, b", `+
		`<https://api.example/.well-known/aauth-resource.json>; rel=aauth-resource`)
	got := aauth.ResourceLinksFromHeader(header.Values("Link"))
	want := []aauth.ResourceLink{
		{Target: linkedResourceMetadata, Issuer: "https://api.example"},
		{Target: "https://billing.example/.well-known/aauth-resource.json", Issuer: "https://billing.example"},
		{Target: "https://docs.example/.well-known/aauth-resource.json", Issuer: "https://docs.example"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("header links = %#v", got)
	}
	if links := aauth.ResourceLinksFromHeader([]string{strings.Repeat(" ", 9<<10) + "<" + linkedResourceMetadata + `>; rel="aauth-resource"`}); links != nil {
		t.Fatalf("oversized Link field was scanned: %#v", links)
	}

	element, err := aauth.ResourceLinkElement("https://api.example")
	if err != nil {
		t.Fatal(err)
	}
	page := []byte(`<!doctype html><html><head>` + element + `
		<LINK href="https://evil.example/steal" rel="aauth-resource">
		<link rel="stylesheet" href="https://billing.example/.well-known/aauth-resource.json">
		<link rel='aauth-resource' href=https://billing.example/.well-known/aauth-resource.json />
		<link rel="aauth-resource" href="/.well-known/aauth-resource.json">
		<linked rel="aauth-resource" href="https://linked.example/.well-known/aauth-resource.json">
		</head><body></body></html>`)
	got = aauth.ResourceLinksFromHTML(page)
	want = []aauth.ResourceLink{
		{Target: linkedResourceMetadata, Issuer: "https://api.example"},
		{Target: "https://billing.example/.well-known/aauth-resource.json", Issuer: "https://billing.example"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("HTML links = %#v", got)
	}
	if links := aauth.ResourceLinksFromHTML(append(make([]byte, 1<<20), page...)); links != nil {
		t.Fatalf("oversized HTML document was scanned: %#v", links)
	}
	if _, err := aauth.FormatResourceLinks("https://api.example/v1"); err == nil {
		t.Fatal("a non-identifier issuer formatted a link")
	}
}
