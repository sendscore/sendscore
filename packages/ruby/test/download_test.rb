require "fileutils"
require "json"
require "minitest/autorun"
require "sendscore"
require "socket"
require "tmpdir"

class DownloadTest < Minitest::Test
  FIXTURES = File.expand_path("../../../conformance/release", __dir__)
  PINS = JSON.parse(File.read(File.join(FIXTURES, "pins.json"))).map { |k, v| [k, [v["archive"], v["binary"]]] }.to_h
  LINUX = %w[linux amd64].freeze

  def setup
    @server = TCPServer.new("127.0.0.1", 0)
    @base = "http://127.0.0.1:#{@server.addr[1]}"
    @thread = Thread.new do
      loop do
        client = @server.accept
        Thread.new(client) { |c| serve(c) }
      end
    end
  end

  def serve(client)
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

  def teardown
    @thread.kill
    @server.close
  end

  def test_installs_the_binary_and_nothing_else
    [%w[linux amd64], %w[darwin arm64], %w[windows amd64]].each do |target|
      Dir.mktmpdir do |tmp|
        cache = File.join(tmp, "cache")
        path = SendScore::Binary.download("0.0.0-test", "#{@base}/good", cache, PINS[target.join("_")], target)
        assert_includes File.read(path), "fake sendscore"
        assert File.executable?(path) unless SendScore::Binary.windows?
        assert_equal [File.basename(path)], Dir.children(cache)
        refute File.exist?(File.join(tmp, "evil"))
      end
    end
  end

  def test_refuses_a_mismatch
    Dir.mktmpdir do |tmp|
      cache = File.join(tmp, "cache")
      assert_raises(SendScore::Error) { SendScore::Binary.download("0.0.0-test", "#{@base}/altered", cache, PINS["linux_amd64"], LINUX) }
      refute File.exist?(cache)
    end
  end

  def test_fails_on_a_missing_release
    Dir.mktmpdir do |tmp|
      assert_raises(SendScore::Error) { SendScore::Binary.download("0.0.0-test", "#{@base}/nothing", File.join(tmp, "cache"), PINS["linux_amd64"], LINUX) }
    end
  end

  def test_refuses_a_binary_that_does_not_match
    Dir.mktmpdir do |tmp|
      cache = File.join(tmp, "cache")
      wrong = [PINS["linux_amd64"][0], "0" * 64]
      assert_raises(SendScore::Error) { SendScore::Binary.download("0.0.0-test", "#{@base}/good", cache, wrong, LINUX) }
      refute File.exist?(cache)
    end
  end

  def test_cached_binary_is_trusted_only_while_it_matches
    Dir.mktmpdir do |tmp|
      pin = PINS["linux_amd64"]
      path = SendScore::Binary.download("0.0.0-test", "#{@base}/good", File.join(tmp, "cache"), pin, LINUX)
      assert SendScore::Binary.matches_pin?(path, pin)
      File.write(path, "planted")
      refute SendScore::Binary.matches_pin?(path, pin)
    end
  end

  def test_no_pin_means_no_download
    assert_raises(SendScore::Error) { SendScore::Binary.pin_for(LINUX, {}) }
  end

  def test_concurrent_first_downloads_all_succeed
    Dir.mktmpdir do |tmp|
      cache = File.join(tmp, "cache")
      threads = Array.new(8) { Thread.new { SendScore::Binary.download("0.0.0-test", "#{@base}/good", cache, PINS["linux_amd64"], LINUX) } }
      threads.each(&:value)
      assert_equal ["sendscore"], Dir.children(cache)
    end
  end
end
