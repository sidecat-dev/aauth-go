alias Sidecat.AAuth.{AgentToken, HttpSig, Jwk, Mission}

defmodule GoAgentRequestVerification do
  def run(path) do
    fixture = path |> File.read!() |> Jason.decode!()
    expect(fixture["schema"] == "aauth.interop.go-agent-request.v0", "schema")

    expected = fixture["expected"]
    request_fixture = fixture["request"]
    headers = request_fixture["headers"]
    {:ok, agent_public} = Base.url_decode64(expected["agent_key"]["x"], padding: false)

    provider_jwks = Jwk.jwks([fixture["issuer_key"]])

    {:ok, claims} =
      AgentToken.verify(
        request_fixture["agent_token"],
        provider_jwks,
        now: fixture["now"],
        request_key: agent_public
      )

    expect(claims["iss"] == fixture["issuer"], "agent-token issuer")
    expect(claims["sub"] == expected["agent"], "agent-token subject")
    expect(claims["ps"] == expected["person_server"], "agent-token person server")

    uri = URI.parse(request_fixture["url"])

    request = %{
      method: request_fixture["method"],
      authority: uri.authority,
      path: uri.path,
      mission: headers["AAuth-Mission"]
    }

    signature_headers = %{
      signature_input: headers["Signature-Input"],
      signature: headers["Signature"],
      signature_key: headers["Signature-Key"]
    }

    expect(
      headers["Signature-Key"] ==
        HttpSig.signature_key_jwt("sig", request_fixture["agent_token"]),
      "agent-token presentation"
    )

    :ok = HttpSig.verify_request(request, signature_headers)
    {:ok, mission} = Mission.parse_header(headers["AAuth-Mission"])
    expect(mission.approver == expected["mission"]["approver"], "mission approver")
    expect(mission.s256 == expected["mission"]["s256"], "mission digest")

    mutated_mission =
      String.replace(
        headers["AAuth-Mission"],
        "s256=\"",
        "s256=\"A",
        global: false
      )

    mutated_request = Map.put(request, :mission, mutated_mission)

    expect(
      HttpSig.verify_request(mutated_request, signature_headers) != :ok,
      "mission mutation control"
    )

    mutated_key =
      String.replace(
        headers["Signature-Key"],
        "sig=jwt;jwt=\"",
        "sig=jwt;jwt=\"A",
        global: false
      )

    expect(
      HttpSig.verify_request(
        request,
        Map.put(signature_headers, :signature_key, mutated_key)
      ) != :ok,
      "Signature-Key mutation control"
    )

    IO.puts(
      Jason.encode!(%{
        schema: "aauth.interop.go-agent-request-verification.v0",
        status: "verified",
        agent: expected["agent"]
      })
    )
  end

  defp expect(true, _name), do: :ok
  defp expect(false, name), do: raise("Go vector failed #{name}")
end

case System.argv() do
  [path] ->
    GoAgentRequestVerification.run(path)

  _ ->
    IO.puts(:stderr, "usage: mix run verify_go_agent_request.exs FIXTURE")
    System.halt(2)
end
