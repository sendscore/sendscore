defmodule SendScore.ConformanceTest do
  use ExUnit.Case, async: true

  @root Path.expand("../../../conformance", __DIR__)
  @cases (@root <> "/cases.json") |> File.read!() |> JSON.decode!() |> Map.fetch!("cases")

  defp path(rel), do: Path.join(@root, rel)

  defp run(%{"command" => "diff"} = c), do: SendScore.diff(path(c["before"]), path(c["after"]))

  defp run(c) do
    given = Map.get(c, "options", %{})
    opts = for k <- ~w(ip mail_from helo tls), Map.has_key?(given, k), do: {String.to_atom(k), given[k]}
    opts = if given["previous"], do: [{:previous, path(given["previous"])} | opts], else: opts
    message = if c["via"] == "stdin", do: {:bytes, File.read!(path(c["message"]))}, else: path(c["message"])
    SendScore.check(message, [{:offline, true} | opts])
  end

  for c <- @cases do
    @c c
    test c["name"] do
      c = @c

      if c["exit"] > 2 do
        assert {:error, %SendScore.Error{exit_code: code}} = run(c)
        assert code == c["exit"]
      else
        assert {:ok, got} = run(c)
        changes = got["changes"] || []
        assert Enum.map(changes, & &1["field"]) == Map.get(c, "changes", [])
        assert changes |> Enum.map(& &1["worsened"]) |> Enum.reject(&is_nil/1) == Map.get(c, "worsened", [])

        if c["command"] == "check" do
          assert got["verdict"] == c["verdict"]
          assert got["ready_to_send"] == c["ready_to_send"]
          assert Map.new(got["checks"], &{&1["id"], &1["status"]}) == c["checks"]
        end
      end
    end
  end
end
