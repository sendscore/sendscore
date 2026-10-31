require "digest"
require "fileutils"
require "net/http"
require "rbconfig"
require "openssl"
require "pathname"
require "rubygems/package"
require "securerandom"
require "sendscore/hashes"
require "stringio"
require "uri"
require "zlib"

module SendScore
  # Finds the CLI, and downloads a release when none is installed.
  module Binary
    RELEASES = "https://github.com/sendscore/sendscore/releases/download".freeze
    MAX_REDIRECTS = 5
    MAX_DOWNLOAD = 100 << 20

    module_function

    # SENDSCORE_BIN, then the pinned version on PATH, then the cache, then a
    # download. A cached binary is checked against its pinned hash every time,
    # so a file planted in the cache is replaced and never run.
    def find
      from_env = ENV["SENDSCORE_BIN"]
      return from_env if from_env && !from_env.empty?

      name = windows? ? "sendscore.exe" : "sendscore"
      ENV.fetch("PATH", "").split(File::PATH_SEPARATOR).each do |dir|
        path = File.join(dir, name)
        return path if absolute?(dir) && File.file?(path) && File.executable?(path) && right_version?(path)
      end
      target = platform
      pin = pin_for(target)
      dir = File.join(cache_root, "sendscore", ENGINE_VERSION)
      cached = File.join(dir, name)
      return cached if matches_pin?(cached, pin)

      download(ENGINE_VERSION, "#{RELEASES}/v#{ENGINE_VERSION}", dir, pin, target)
    rescue SystemCallError => e
      raise Error.new("could not find or install the CLI: #{e.message}", 0)
    end

    def absolute?(path)
      !path.empty? && Pathname.new(path).absolute?
    end

    def right_version?(path)
      code, stdout, = SendScore.capture(path, ["--version"], nil, 10)
      code.zero? && stdout.split.last.to_s.sub(/\Av/, "") == ENGINE_VERSION
    rescue Error, SystemCallError
      false
    end

    # The [archive, binary] hashes of a platform. With none, nothing is trusted.
    def pin_for(target, pins = HASHES)
      key = target.join("_")
      pins.fetch(key) do
        raise Error.new("this package has no pinned hash for #{key}, so it will not download a CLI. Install the matching sendscore on PATH, or set SENDSCORE_BIN.", 0)
      end
    end

    # Whether a file exists and is exactly the pinned binary.
    def matches_pin?(path, pin)
      File.file?(path) && Digest::SHA256.file(path).hexdigest == pin[1]
    rescue SystemCallError
      false
    end

    def windows?
      RbConfig::CONFIG["host_os"].match?(/mswin|mingw/)
    end

    def platform
      os = case RbConfig::CONFIG["host_os"]
           when /linux/ then "linux"
           when /darwin/ then "darwin"
           when /mswin|mingw/ then "windows"
           end
      arch = { "x86_64" => "amd64", "amd64" => "amd64", "arm64" => "arm64", "aarch64" => "arm64" }[RbConfig::CONFIG["host_cpu"]]
      raise Error.new("no SendScore build for #{RbConfig::CONFIG['host_os']} on #{RbConfig::CONFIG['host_cpu']}", 0) unless os && arch

      [os, arch]
    end

    def cache_root
      home = Dir.home
      case platform.first
      when "darwin" then File.join(home, "Library", "Caches")
      when "windows" then ENV["LOCALAPPDATA"] || File.join(home, "AppData", "Local")
      else
        xdg = ENV["XDG_CACHE_HOME"].to_s
        absolute?(xdg) ? xdg : File.join(home, ".cache")
      end
    end

    def fetch(url, redirects = MAX_REDIRECTS)
      uri = URI(url)
      options = { use_ssl: uri.scheme == "https", open_timeout: 30, read_timeout: 60 }
      Net::HTTP.start(uri.host, uri.port, options) do |http|
        http.request_get(uri) do |res|
          case res
          when Net::HTTPSuccess
            body = String.new(encoding: Encoding::BINARY)
            res.read_body do |part|
              body << part
              raise Error.new("download of #{url} is too large", 0) if body.bytesize > MAX_DOWNLOAD
            end
            return body
          when Net::HTTPRedirection
            raise Error.new("too many redirects from #{url}", 0) if redirects.zero?

            return fetch(URI.join(url, res["location"]).to_s, redirects - 1)
          else
            raise Error.new("download of #{url} answered #{res.code}", 0)
          end
        end
      end
    rescue SystemCallError, SocketError, IOError, Timeout::Error, OpenSSL::SSL::SSLError, EOFError => e
      raise Error.new("download of #{url} failed: #{e.message}", 0)
    end

    # One file, by its exact name, so no path in the archive is ever used.
    def from_tar(gz, name)
      tar = Zlib.gunzip(gz)
      Gem::Package::TarReader.new(StringIO.new(tar)) do |reader|
        reader.each { |entry| return entry.read if entry.full_name == name && entry.file? }
      end
      nil
    end

    def from_zip(zip, name)
      zip = zip.dup.force_encoding(Encoding::BINARY)
      eocd = zip.rindex("PK\x05\x06".b)
      return nil unless eocd

      count = zip[eocd + 10, 2].unpack1("v")
      at = zip[eocd + 16, 4].unpack1("V")
      count.times do
        method = zip[at + 10, 2].unpack1("v")
        packed = zip[at + 20, 4].unpack1("V")
        name_len, extra, comment = zip[at + 28, 6].unpack("vvv")
        local = zip[at + 42, 4].unpack1("V")
        if zip[at + 46, name_len] == name.b
          local_name, local_extra = zip[local + 26, 4].unpack("vv")
          data = zip[local + 30 + local_name + local_extra, packed]
          return method.zero? ? data : Zlib::Inflate.new(-Zlib::MAX_WBITS).inflate(data)
        end
        at += 46 + name_len + extra + comment
      end
      nil
    end

    # Downloads a release into dir, and returns the binary's path. The archive
    # must match its pin before anything is extracted, and the binary must
    # match its pin before it reaches the disk.
    def download(version, base, dir, pin, target = platform)
      os, arch = target
      exe = os == "windows" ? "sendscore.exe" : "sendscore"
      ext = os == "windows" ? "zip" : "tar.gz"
      name = "sendscore_#{version}_#{os}_#{arch}.#{ext}"
      archive = fetch("#{base}/#{name}")
      raise Error.new("#{name} does not match its pinned hash", 0) if Digest::SHA256.hexdigest(archive) != pin[0]

      begin
        binary = os == "windows" ? from_zip(archive, exe) : from_tar(archive, exe)
      rescue Zlib::Error, Gem::Package::Error => e
        raise Error.new("could not read #{name}: #{e.message}", 0)
      end
      raise Error.new("#{name} has no #{exe}", 0) unless binary
      raise Error.new("the binary in #{name} does not match its pinned hash", 0) if Digest::SHA256.hexdigest(binary) != pin[1]

      install(binary, dir, exe)
    end

    def install(binary, dir, exe)
      FileUtils.mkdir_p(dir)
      path = File.join(dir, exe)
      # Unique per call, so threads and processes never share a partial file.
      temp = "#{path}.#{Process.pid}.#{SecureRandom.hex(8)}.download"
      begin
        File.binwrite(temp, binary)
        File.chmod(0o755, temp)
        File.rename(temp, path)
      ensure
        FileUtils.rm_f(temp)
      end
      path
    rescue SystemCallError => e
      raise Error.new("could not write to #{dir}: #{e.message}", 0)
    end
  end
end
