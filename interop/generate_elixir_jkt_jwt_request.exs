alias Sidecat.AAuth.{HttpSig, JktJwt, Jwk}

case System.argv() do
  [output] ->
    {source_status, 0} =
      System.cmd(
        "git",
        [
          "status",
          "--porcelain=v1",
          "--",
          "lib/sidecat/aauth",
          "mix.exs",
          "mix.lock"
        ],
        stderr_to_stdout: true
      )

    if String.trim(source_status) != "" do
      raise("sidecat-beam AAuth source or dependency files are not clean")
    end

    {commit, 0} = System.cmd("git", ["rev-parse", "HEAD"], stderr_to_stdout: true)
    commit = String.trim(commit)

    unless Regex.match?(~r/^[0-9a-f]{40}$/, commit) do
      raise("sidecat-beam commit identity is invalid")
    end

    durable_seed = :binary.copy(<<71>>, 32)
    ephemeral_seed = :binary.copy(<<83>>, 32)
    {durable_public, durable_private} =
      :crypto.generate_key(:eddsa, :ed25519, durable_seed)

    {ephemeral_public, ephemeral_private} =
      :crypto.generate_key(:eddsa, :ed25519, ephemeral_seed)

    now = 2_000_000_100
    durable = %{pub: durable_public, priv: durable_private}
    ephemeral = %{pub: ephemeral_public, priv: ephemeral_private}
    {:ok, delegation} =
      JktJwt.mint(durable, ephemeral_public, now: now, exp: now + 300)

    request = %{
      method: "POST",
      authority: "provider.example",
      path: "/refresh"
    }

    signed =
      HttpSig.sign_request(
        request,
        ephemeral,
        created: now,
        signature_key: HttpSig.signature_key_jkt_jwt("sig", delegation)
      )

    fixture = %{
      "schema" => "aauth.interop.elixir-jkt-jwt-request.v0",
      "generator" => %{
        "repository" => "https://gitlab.com/sidecat-dev/sidecat-beam",
        "commit" => commit
      },
      "now" => now,
      "expected" => %{
        "identity" => "urn:jkt:sha-256:" <> Jwk.thumbprint(durable_public),
        "identity_key" => Jwk.public_jwk(durable_public),
        "request_key" => Jwk.public_jwk(ephemeral_public)
      },
      "request" => %{
        "method" => "POST",
        "url" => "https://provider.example/refresh",
        "headers" => %{
          "Signature-Input" => signed.signature_input,
          "Signature" => signed.signature,
          "Signature-Key" => signed.signature_key
        }
      }
    }

    File.mkdir_p!(Path.dirname(output))
    File.write!(output, Jason.encode!(fixture, pretty: true) <> "\n")

  _ ->
    IO.puts(
      :stderr,
      "usage: mix run generate_elixir_jkt_jwt_request.exs OUTPUT"
    )

    System.halt(2)
end
