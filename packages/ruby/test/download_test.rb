require "fileutils"
require "minitest/autorun"
require "sendscore"
require "socket"
require "tmpdir"

class DownloadTest < Minitest::Test
  FIXTURES = File.expand_path("../../../conformance/release", __dir__)

  def setup
    @server = TCPServer.new("127.0.0.1", 0)
    @base = "http://127.0.0.1:#{@server.addr[1]}"
    @thread = Thread.new do
      loop do
        client = @server.accept
        request = client.gets.to_s.split[1].to_s
        while (line = client.gets) && line != "\r\n"; end
        path = File.join(FIXTURES, request)
        if File.file?(path)
          body = File.binread(path)
          client.write("HTTP/1.1 200 OK\r\nContent-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n", body)
        else
          client.write("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        end
        client.close
      end
    end
  end

  def teardown
    @thread.kill
    @server.close
  end

  def test_installs_the_binary_and_nothing_else
    [%w[linux amd64], %w[darwin arm64], %w[windows amd64]].each do |target|
      Dir.mktmpdir do |tmp|
        cache = File.join(tmp, "cache")
        path = SendScore::Binary.download("0.0.0-test", "#{@base}/good", cache, target)
        assert_includes File.read(path), "fake sendscore"
        assert File.executable?(path)
        assert_equal [File.basename(path)], Dir.children(cache)
        refute File.exist?(File.join(tmp, "evil"))
      end
    end
  end

  def test_refuses_a_mismatch
    Dir.mktmpdir do |tmp|
      cache = File.join(tmp, "cache")
      assert_raises(SendScore::Error) { SendScore::Binary.download("0.0.0-test", "#{@base}/tampered", cache, %w[linux amd64]) }
      refute File.exist?(cache)
    end
  end

  def test_fails_on_a_missing_release
    Dir.mktmpdir do |tmp|
      assert_raises(SendScore::Error) { SendScore::Binary.download("0.0.0-test", "#{@base}/nothing", File.join(tmp, "cache"), %w[linux amd64]) }
    end
  end
end
