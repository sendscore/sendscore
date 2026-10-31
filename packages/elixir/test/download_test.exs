defmodule SendScore.DownloadTest do
  use ExUnit.Case, async: true

  alias SendScore.{Binary, Error}

  @fixtures Path.expand("../../../conformance/release", __DIR__)

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
      path = Binary.download("0.0.0-test", "#{base}/good", cache, target)
      assert File.read!(path) =~ "fake sendscore"
      assert File.ls!(cache) == [Path.basename(path)]
      refute File.exists?(Path.join(tmp, "evil"))
    end
  end

  test "refuses a mismatch", %{base: base, tmp: tmp} do
    cache = Path.join(tmp, "cache")
    assert_raise Error, fn -> Binary.download("0.0.0-test", "#{base}/tampered", cache, {"linux", "amd64"}) end
    refute File.exists?(cache)
  end

  test "fails on a missing release", %{base: base, tmp: tmp} do
    assert_raise Error, fn ->
      Binary.download("0.0.0-test", "#{base}/nothing", Path.join(tmp, "cache"), {"linux", "amd64"})
    end
  end
end
