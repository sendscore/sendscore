defmodule SendScore.DownloadTest do
  use ExUnit.Case, async: true

  alias SendScore.{Binary, Error}

  @fixtures Path.expand("../../../conformance/release", __DIR__)
  @pins (@fixtures <> "/pins.json")
        |> File.read!()
        |> JSON.decode!()
        |> Map.new(fn {k, v} -> {k, {v["archive"], v["binary"]}} end)
  @linux {"linux", "amd64"}

  defp serve(socket) do
    {:ok, client} = :gen_tcp.accept(socket)
    {:ok, request} = :gen_tcp.recv(client, 0, 5000)
    [_, path | _] = String.split(request)

    reply =
      case File.read(Path.join(@fixtures, path)) do
        {:ok, body} -> "HTTP/1.1 200 OK\r\nContent-Length: #{byte_size(body)}\r\nConnection: close\r\n\r\n" <> body
        _ -> "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
      end

    :gen_tcp.send(client, reply)
    :gen_tcp.close(client)
    serve(socket)
  end

  setup do
    {:ok, socket} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}, reuseaddr: true])
    {:ok, port} = :inet.port(socket)
    start_supervised!({Task, fn -> serve(socket) end})
    tmp = Path.join(System.tmp_dir!(), "sendscore-#{System.unique_integer([:positive])}")
    File.mkdir_p!(tmp)
    on_exit(fn -> File.rm_rf!(tmp) end)
    {:ok, base: "http://127.0.0.1:#{port}", tmp: tmp}
  end

  test "installs the binary and nothing else", %{base: base, tmp: tmp} do
    for {target, i} <- Enum.with_index([{"linux", "amd64"}, {"darwin", "arm64"}, {"windows", "amd64"}]) do
      cache = Path.join(tmp, "cache#{i}")
      {os, arch} = target
      path = Binary.download("0.0.0-test", "#{base}/good", cache, @pins["#{os}_#{arch}"], target)
      assert File.read!(path) =~ "fake sendscore"
      assert File.ls!(cache) == [Path.basename(path)]
      refute File.exists?(Path.join(tmp, "evil"))
    end
  end

  test "refuses a mismatch", %{base: base, tmp: tmp} do
    cache = Path.join(tmp, "cache")
    assert_raise Error, fn -> Binary.download("0.0.0-test", "#{base}/altered", cache, @pins["linux_amd64"], @linux) end
    refute File.exists?(cache)
  end

  test "fails on a missing release", %{base: base, tmp: tmp} do
    assert_raise Error, fn ->
      Binary.download("0.0.0-test", "#{base}/nothing", Path.join(tmp, "cache"), @pins["linux_amd64"], @linux)
    end
  end

  test "refuses a binary that does not match", %{base: base, tmp: tmp} do
    cache = Path.join(tmp, "cache")
    wrong = {elem(@pins["linux_amd64"], 0), String.duplicate("0", 64)}
    assert_raise Error, fn -> Binary.download("0.0.0-test", "#{base}/good", cache, wrong, @linux) end
    refute File.exists?(cache)
  end

  test "a cached binary is trusted only while it matches", %{base: base, tmp: tmp} do
    pin = @pins["linux_amd64"]
    path = Binary.download("0.0.0-test", "#{base}/good", Path.join(tmp, "cache"), pin, @linux)
    assert Binary.matches_pin?(path, pin)
    File.write!(path, "planted")
    refute Binary.matches_pin?(path, pin)
  end

  test "no pin means no download" do
    assert_raise Error, fn -> Binary.pin_for(@linux, %{}) end
  end
end
