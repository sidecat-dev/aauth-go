alias Sidecat.AAuth.{HttpSig, JktJwt, Jwk}

defmodule GoJKTJWTRequestVerification do
  def run(path) do
    fixture = path |> File.read!() |> Jason.decode!()
    expect(fixture["schema"] == "aauth.interop.go-jkt-jwt-request.v0", "schema")

    request_fixture = fixture["request"]
    headers = request_fixture["headers"]
    [_, delegation] =
      Regex.run(~r/^sig=jkt-jwt;jwt="([^"]+)"$/, headers["Signature-Key"])

    {:ok, identity_public} =
      Base.url_decode64(fixture["expected"]["identity_key"]["x"], padding: false)

    {:ok, request_public} =
      Base.url_decode64(fixture["expected"]["request_key"]["x"], padding: false)

    {:ok, resolved} = JktJwt.resolve(delegation, now: fixture["now"])
    expect(resolved.jkt == fixture["expected"]["identity"], "durable identity")
    expect(resolved.jkt == "urn:jkt:sha-256:" <> Jwk.thumbprint(identity_public), "identity thumbprint")
    expect(resolved.key == request_public, "delegated request key")

    uri = URI.parse(request_fixture["url"])

    request = %{
      method: request_fixture["method"],
      authority: uri.authority,
      path: uri.path
    }

    signature_headers = %{
      signature_input: headers["Signature-Input"],
      signature: headers["Signature"],
      signature_key: headers["Signature-Key"]
    }

    :ok = HttpSig.verify_request(request, signature_headers, now: fixture["now"])

    mutated_key =
      String.replace(
        headers["Signature-Key"],
        ~s(sig=jkt-jwt;jwt="),
        ~s(sig=jkt-jwt;jwt="A),
        global: false
      )

    expect(
      HttpSig.verify_request(
        request,
        Map.put(signature_headers, :signature_key, mutated_key),
        now: fixture["now"]
      ) != :ok,
      "Signature-Key mutation control"
    )

    IO.puts(
      Jason.encode!(%{
        schema: "aauth.interop.go-jkt-jwt-request-verification.v0",
        status: "verified",
        identity: resolved.jkt
      })
    )
  end

  defp expect(true, _name), do: :ok
  defp expect(false, name), do: raise("Go jkt-jwt vector failed #{name}")
end

case System.argv() do
  [path] ->
    GoJKTJWTRequestVerification.run(path)

  _ ->
    IO.puts(:stderr, "usage: mix run verify_go_jkt_jwt_request.exs FIXTURE")
    System.halt(2)
end
