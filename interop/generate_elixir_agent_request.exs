alias Sidecat.AAuth.{AgentToken, HttpSig, Jwk, Mission}

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

    provider_seed = :binary.copy(<<17>>, 32)
    agent_seed = :binary.copy(<<29>>, 32)
    {provider_public, provider_private} = :crypto.generate_key(:eddsa, :ed25519, provider_seed)

    {agent_public, agent_private} = :crypto.generate_key(:eddsa, :ed25519, agent_seed)

    provider = %{
      pub: provider_public,
      priv: provider_private,
      kid: Jwk.thumbprint(provider_public)
    }

    agent = %{pub: agent_public, priv: agent_private}
    now = 2_000_000_100
    issuer = "https://provider.example"
    person_server = "https://person.example"
    agent_identifier = "aauth:interop@provider.example"

    {:ok, agent_token} =
      AgentToken.mint(
        %{
          iss: issuer,
          sub: agent_identifier,
          cnf_pub: agent_public,
          ps: person_server,
          jti: "elixir-go-agent-token",
          iat: 2_000_000_000,
          exp: 2_000_003_600
        },
        provider,
        now: now
      )

    mission_bytes =
      ~s({"description":"Exercise an independent Elixir peer.","tools":[{"name":"records.read","description":"Read one admitted record."}]})

    {:ok, {_bytes, mission}} = Mission.mint(mission_bytes, person_server)
    mission_header = Mission.to_header_value(mission)

    request = %{
      method: "GET",
      authority: "resource.example",
      path: "/authorize",
      mission: mission_header
    }

    signed =
      HttpSig.sign_request(
        request,
        agent,
        created: now,
        signature_key: HttpSig.signature_key_jwt("sig", agent_token)
      )

    fixture = %{
      "schema" => "aauth.interop.elixir-agent-request.v0",
      "generator" => %{
        "repository" => "https://gitlab.com/sidecat-dev/sidecat-beam",
        "commit" => commit
      },
      "now" => now,
      "issuer" => issuer,
      "issuer_key" => Jwk.public_jwk(provider_public, provider.kid),
      "expected" => %{
        "agent" => agent_identifier,
        "person_server" => person_server,
        "agent_key" => Jwk.public_jwk(agent_public, Jwk.thumbprint(agent_public)),
        "mission" => mission
      },
      "request" => %{
        "method" => "GET",
        "url" => "https://resource.example/authorize",
        "headers" => %{
          "AAuth-Mission" => mission_header,
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
      "usage: mix run generate_elixir_agent_request.exs OUTPUT"
    )

    System.halt(2)
end
