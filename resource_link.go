package aauth

import (
	"bytes"
	"errors"
	"fmt"
	"html"
	"net/http"
	"strings"
)

// ResourceLinkRelation is the link relation type that names the resource
// metadata document governing what a response or an HTML page describes.
const ResourceLinkRelation = "aauth-resource"

const (
	resourceMetadataSuffix = "/.well-known/" + ResourceDiscoveryDocument
	// maxResourceLinkField bounds the Link field value that is scanned.
	maxResourceLinkField = 8 << 10
	// maxResourceLinkDocument bounds the HTML document that is scanned.
	maxResourceLinkDocument = 1 << 20
)

// ResourceLink is one admissible aauth-resource link: a server identifier
// followed by /.well-known/aauth-resource.json. It is a statement by whoever
// controls the response or page that carried it, not by the resource it names,
// and it plays no part in key discovery or in what a response requires.
type ResourceLink struct {
	// Target is the absolute metadata URL, exactly as the link carried it.
	Target string
	// Issuer is Target without the well-known suffix. A metadata document
	// fetched from Target is accepted only when its issuer equals Issuer.
	Issuer string
}

// ResourceMetadataURL returns the well-known metadata URL of a resource
// identifier.
func ResourceMetadataURL(issuer string) (string, error) {
	if err := ValidateServerIdentifier(issuer); err != nil {
		return "", fmt.Errorf("aauth: resource link issuer: %w", err)
	}
	return issuer + resourceMetadataSuffix, nil
}

// ParseResourceLinkTarget accepts exactly a server identifier followed by
// /.well-known/aauth-resource.json. A relative target, a path before the
// suffix, a query, a fragment, a port, userinfo, or any other form is refused,
// and an Agent must not fetch it.
func ParseResourceLinkTarget(target string) (ResourceLink, error) {
	issuer, ok := strings.CutSuffix(target, resourceMetadataSuffix)
	if !ok {
		return ResourceLink{}, errors.New("aauth: resource link target must end with " + resourceMetadataSuffix)
	}
	if err := ValidateServerIdentifier(issuer); err != nil {
		return ResourceLink{}, fmt.Errorf("aauth: resource link target: %w", err)
	}
	return ResourceLink{Target: target, Issuer: issuer}, nil
}

// FormatResourceLinks returns a Link field value naming the metadata document
// of each resource identifier, in order. A response that describes several
// resources may carry one link for each.
func FormatResourceLinks(issuers ...string) (string, error) {
	if len(issuers) == 0 {
		return "", errors.New("aauth: at least one resource identifier is required")
	}
	links := make([]string, 0, len(issuers))
	for _, issuer := range issuers {
		target, err := ResourceMetadataURL(issuer)
		if err != nil {
			return "", err
		}
		links = append(links, "<"+target+`>; rel="`+ResourceLinkRelation+`"`)
	}
	return strings.Join(links, ", "), nil
}

// AddResourceLinks adds one Link field naming the metadata document of each
// resource identifier, for example to the response of a developer portal or
// of the page at a resource's documentation_uri.
func AddResourceLinks(header http.Header, issuers ...string) error {
	if header == nil {
		return errors.New("aauth: response header is required")
	}
	value, err := FormatResourceLinks(issuers...)
	if err != nil {
		return err
	}
	header.Add("Link", value)
	return nil
}

// ResourceLinkElement returns an HTML link element for the head of a page,
// such as the one at a resource's documentation_uri, naming the resource's
// metadata document.
func ResourceLinkElement(issuer string) (string, error) {
	target, err := ResourceMetadataURL(issuer)
	if err != nil {
		return "", err
	}
	return `<link rel="` + ResourceLinkRelation + `" href="` + html.EscapeString(target) + `">`, nil
}

// ResourceLinksFromHeader returns the admissible aauth-resource targets of the
// Link field lines of one response, in order and without duplicates. Links
// with another relation and targets of any other form are omitted. Field
// values longer than 8 KiB in total are not scanned. The links say nothing
// about the response that carries them; a requirement is read only from
// AAuth-Requirement.
func ResourceLinksFromHeader(values []string) []ResourceLink {
	field := strings.Join(values, ", ")
	if len(field) > maxResourceLinkField {
		return nil
	}
	var links []ResourceLink
	for _, value := range splitLinkValues(field) {
		target, rel, ok := parseLinkValue(value)
		if !ok || !hasResourceRelation(rel) {
			continue
		}
		links = appendResourceLink(links, target)
	}
	return links
}

// ResourceLinksFromHTML returns the admissible aauth-resource targets of the
// link elements in one HTML document, in order and without duplicates. The
// document is untrusted input: it is scanned, never rendered or executed, and
// a document larger than 1 MiB is not scanned. Every link element is read,
// not only those in head, and an href is used as written, without resolving it
// against the page URL, so only an absolute target can be admissible.
func ResourceLinksFromHTML(document []byte) []ResourceLink {
	if len(document) > maxResourceLinkDocument {
		return nil
	}
	var links []ResourceLink
	for index := 0; index+5 < len(document); {
		if !bytes.EqualFold(document[index:index+5], []byte("<link")) || !isLinkTagBoundary(document[index+5]) {
			index++
			continue
		}
		end := bytes.IndexByte(document[index:], '>')
		if end < 0 {
			break
		}
		if target, rel, ok := parseLinkElement(string(document[index+5 : index+end])); ok && hasResourceRelation(rel) {
			links = appendResourceLink(links, target)
		}
		index += end + 1
	}
	return links
}

func appendResourceLink(links []ResourceLink, target string) []ResourceLink {
	link, err := ParseResourceLinkTarget(target)
	if err != nil {
		return links
	}
	for _, existing := range links {
		if existing.Target == link.Target {
			return links
		}
	}
	return append(links, link)
}

func hasResourceRelation(rel string) bool {
	for _, relation := range strings.Fields(rel) {
		if strings.EqualFold(relation, ResourceLinkRelation) {
			return true
		}
	}
	return false
}

// splitLinkValues splits a Link field at commas outside quotes and outside the
// angle brackets of a target.
func splitLinkValues(field string) []string {
	var values []string
	start, quoted, bracketed := 0, false, false
	for index, character := range field {
		switch {
		case character == '"' && !bracketed:
			quoted = !quoted
		case character == '<' && !quoted:
			bracketed = true
		case character == '>' && !quoted:
			bracketed = false
		case character == ',' && !quoted && !bracketed:
			if value := strings.TrimSpace(field[start:index]); value != "" {
				values = append(values, value)
			}
			start = index + 1
		}
	}
	if value := strings.TrimSpace(field[start:]); value != "" {
		values = append(values, value)
	}
	return values
}

func parseLinkValue(value string) (string, string, bool) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(value), "<")
	if !ok {
		return "", "", false
	}
	target, parameters, ok := strings.Cut(rest, ">")
	if !ok {
		return "", "", false
	}
	rel, found := "", false
	for _, parameter := range strings.Split(parameters, ";") {
		name, raw, ok := strings.Cut(strings.TrimSpace(parameter), "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(name), "rel") {
			continue
		}
		rel, found = unquoteLinkParameter(strings.TrimSpace(raw)), true
	}
	return target, rel, found
}

func unquoteLinkParameter(value string) string {
	for _, quote := range []string{`"`, `'`} {
		if len(value) >= 2 && strings.HasPrefix(value, quote) && strings.HasSuffix(value, quote) {
			return value[1 : len(value)-1]
		}
	}
	return value
}

func isLinkTagBoundary(character byte) bool {
	return character == '/' || character == ' ' || character == '\t' || character == '\n' ||
		character == '\r' || character == '\f'
}

// parseLinkElement reads the href and rel attributes of one link element.
// Attribute values are entity-decoded as HTML defines.
func parseLinkElement(attributes string) (string, string, bool) {
	href, rel := "", ""
	hasHref, hasRel := false, false
	rest := attributes
	for {
		start := strings.IndexFunc(rest, isASCIILetter)
		if start < 0 {
			break
		}
		rest = rest[start:]
		nameEnd := strings.IndexFunc(rest, func(character rune) bool {
			return !isASCIILetter(character) && !(character >= '0' && character <= '9') && character != '-'
		})
		if nameEnd < 0 {
			nameEnd = len(rest)
		}
		name := rest[:nameEnd]
		rest = strings.TrimLeft(rest[nameEnd:], " \t\n\r\f")
		value, ok := strings.CutPrefix(rest, "=")
		if !ok {
			continue
		}
		value = strings.TrimLeft(value, " \t\n\r\f")
		attribute, next, ok := attributeValue(value)
		if !ok {
			return "", "", false
		}
		switch {
		case strings.EqualFold(name, "href"):
			href, hasHref = html.UnescapeString(attribute), true
		case strings.EqualFold(name, "rel"):
			rel, hasRel = html.UnescapeString(attribute), true
		}
		rest = next
	}
	return href, rel, hasHref && hasRel
}

func attributeValue(value string) (string, string, bool) {
	if value == "" {
		return "", "", false
	}
	if quote := value[0]; quote == '"' || quote == '\'' {
		end := strings.IndexByte(value[1:], quote)
		if end < 0 {
			return "", "", false
		}
		return value[1 : 1+end], value[2+end:], true
	}
	end := strings.IndexAny(value, " \t\n\r\f>")
	if end < 0 {
		end = len(value)
	}
	return value[:end], value[end:], true
}

func isASCIILetter(character rune) bool {
	return character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z'
}
