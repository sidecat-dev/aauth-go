package aauth_test

import (
	"testing"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

func TestEncodeInteractionQuestionProducesSourceShapedDocument(t *testing.T) {
	t.Parallel()

	request := aauth.InteractionQuestion{
		Description: "The itinerary needs a **decision**.",
		Question:    "Should I choose the refundable option?",
	}
	document, err := aauth.EncodeInteractionQuestion(request)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"type":"question","description":"The itinerary needs a **decision**.","question":"Should I choose the refundable option?"}`
	if string(document.ExactJSON) != want || document.Question != request {
		t.Fatalf("interaction question = %#v, JSON=%s", document.Question, document.ExactJSON)
	}
}

func TestDecodeInteractionQuestionPreservesExactBytesAndAdditiveMembers(t *testing.T) {
	t.Parallel()

	mission := aauth.MissionS256([]byte("interaction mission"))
	exact := []byte("{\n" +
		`  "extension": {"trace": [1, 2]},` + "\n" +
		`  "question": "Which **route** should I take?",` + "\n" +
		`  "type": "question",` + "\n" +
		`  "description": "A route decision is required.",` + "\n" +
		`  "mission_s256": "` + mission + `"` + "\n" +
		"}")
	wantExact := append([]byte(nil), exact...)
	document, err := aauth.DecodeInteractionQuestion(exact)
	if err != nil {
		t.Fatal(err)
	}
	exact[0] = '['
	if string(document.ExactJSON) != string(wantExact) || document.Question.MissionS256 != mission ||
		document.Question.Description != "A route decision is required." ||
		document.Question.Question != "Which **route** should I take?" {
		t.Fatalf("decoded interaction question = %#v, JSON=%s", document.Question, document.ExactJSON)
	}
}

func TestInteractionQuestionValidationRejectsInvalidOrRelayOnlyValues(t *testing.T) {
	t.Parallel()

	mission := aauth.MissionS256([]byte("interaction mission"))
	validPrefix := `{"type":"question","question":"Choose a route?"`
	for _, test := range []struct {
		name string
		body []byte
	}{
		{name: "not object", body: []byte(`[]`)},
		{name: "missing type", body: []byte(`{"question":"Choose?"}`)},
		{name: "wrong type", body: []byte(`{"type":"interaction","question":"Choose?"}`)},
		{name: "missing question", body: []byte(`{"type":"question"}`)},
		{name: "blank question", body: []byte(`{"type":"question","question":"  \t"}`)},
		{name: "null question", body: []byte(`{"type":"question","question":null}`)},
		{name: "duplicate type", body: []byte(`{"type":"question","type":"question","question":"Choose?"}`)},
		{name: "case variant", body: []byte(`{"Type":"question","question":"Choose?"}`)},
		{name: "relay URL", body: []byte(validPrefix + `,"url":"https://resource.example/act"}`)},
		{name: "relay code", body: []byte(validPrefix + `,"code":"ABCD-EFGH"}`)},
		{name: "relay max wait", body: []byte(validPrefix + `,"max_wait":30}`)},
		{name: "null mission", body: []byte(validPrefix + `,"mission_s256":null}`)},
		{name: "empty mission", body: []byte(validPrefix + `,"mission_s256":""}`)},
		{name: "invalid mission", body: []byte(validPrefix + `,"mission_s256":"not-a-digest"}`)},
		{name: "trailing JSON", body: []byte(validPrefix + `}{}`)},
		{name: "invalid UTF-8", body: append(append([]byte(nil), []byte(validPrefix+`,"description":"`)...), append([]byte{0xff}, []byte(`"}`)...)...)},
		{name: "valid mission control", body: []byte(validPrefix + `,"mission_s256":"` + mission + `"}`)},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := aauth.DecodeInteractionQuestion(test.body)
			if test.name == "valid mission control" {
				if err != nil {
					t.Fatalf("valid mission question = %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("invalid interaction question was accepted: %s", test.body)
			}
		})
	}

	for _, question := range []aauth.InteractionQuestion{
		{},
		{Question: "  \n"},
		{Question: string([]byte{0xff})},
		{Question: "Choose?", Description: string([]byte{0xff})},
		{Question: "Choose?", MissionS256: "not-a-digest"},
	} {
		if _, err := aauth.EncodeInteractionQuestion(question); err == nil {
			t.Fatalf("invalid interaction question was encoded: %#v", question)
		}
	}
}

func TestInteractionAnswerRoundTripAndValidation(t *testing.T) {
	t.Parallel()

	encoded, err := aauth.EncodeInteractionAnswer(aauth.InteractionAnswer{Answer: "Use the refundable option."})
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded.ExactJSON) != `{"answer":"Use the refundable option."}` ||
		encoded.Answer.Answer != "Use the refundable option." {
		t.Fatalf("encoded answer = %#v, JSON=%s", encoded.Answer, encoded.ExactJSON)
	}

	exact := []byte("{\n  \"answer\": \"Yes.\",\n  \"extension\": true\n}")
	wantExact := append([]byte(nil), exact...)
	decoded, err := aauth.DecodeInteractionAnswer(exact)
	if err != nil {
		t.Fatal(err)
	}
	exact[0] = '['
	if decoded.Answer.Answer != "Yes." || string(decoded.ExactJSON) != string(wantExact) {
		t.Fatalf("decoded answer = %#v, JSON=%s", decoded.Answer, decoded.ExactJSON)
	}

	for _, body := range [][]byte{
		[]byte(`[]`),
		[]byte(`{}`),
		[]byte(`{"answer":null}`),
		[]byte(`{"answer":1}`),
		[]byte(`{"Answer":"yes"}`),
		[]byte(`{"answer":"yes","answer":"no"}`),
		append([]byte(`{"answer":"`), append([]byte{0xff}, []byte(`"}`)...)...),
	} {
		if _, err := aauth.DecodeInteractionAnswer(body); err == nil {
			t.Fatalf("invalid interaction answer was accepted: %q", body)
		}
	}
	if _, err := aauth.EncodeInteractionAnswer(aauth.InteractionAnswer{Answer: string([]byte{0xff})}); err == nil {
		t.Fatal("invalid UTF-8 interaction answer was encoded")
	}
}
