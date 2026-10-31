require "digest"
require "fileutils"
require "net/http"
require "rbconfig"
require "rubygems/package"
require "stringio"
require "tempfile"
require "uri"
require "zlib"

module SendScore
  # Finds the CLI, and downloads a release when none is installed.
  module Binary
    RELEASES = "https://github.com/sendscore/sendscore/releases/download".freeze
    MAX_REDIRECTS = 5

    module_function

    # SENDSCORE_BIN, then PATH, then the cache, then a download.
    def find
      from_env = ENV["SENDSCORE_BIN"]
      return from_env if from_env && !from_env.empty?

      name = windows? ? "sendscore.exe" : "sendscore"
      ENV.fetch("PATH", "").split(File::PATH_SEPARATOR).each do |dir|
        path = File.join(dir, name)
        return path if !dir.empty? && File.file?(path) && File.executable?(path)
      end
      dir = File.join(cache_root, "sendscore", ENGINE_VERSION)
      cached = File.join(dir, name)
      return cached if File.executable?(cached)

      download(ENGINE_VERSION, "#{RELEASES}/v#{ENGINE_VERSION}", dir)
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
      else ENV["XDG_CACHE_HOME"] || File.join(home, ".cache")
      end
    end

    def fetch(url, redirects = MAX_REDIRECTS)
      res = Net::HTTP.get_response(URI(url))
      case res
      when Net::HTTPSuccess then res.body
      when Net::HTTPRedirection
        raise Error.new("too many redirects from #{url}", 0) if redirects.zero?

        fetch(URI.join(url, res["location"]).to_s, redirects - 1)
      else
        raise Error.new("download of #{url} answered #{res.code}", 0)
      end
    rescue SystemCallError, SocketError, IOError => e
      raise Error.new("download of #{url} failed: #{e.message}", 0)
    end

    def expected_hash(checksums, name)
      checksums.each_line do |line|
        hash, file = line.split
        return hash.downcase if file == name
      end
      raise Error.new("checksums.txt does not list #{name}", 0)
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
    # is checked against checksums.txt before anything is extracted, so a
    # binary that does not match never reaches the disk.
    def download(version, base, dir, target = platform)
      os, arch = target
      exe = os == "windows" ? "sendscore.exe" : "sendscore"
      ext = os == "windows" ? "zip" : "tar.gz"
      name = "sendscore_#{version}_#{os}_#{arch}.#{ext}"
      checksums = fetch("#{base}/checksums.txt")
      archive = fetch("#{base}/#{name}")
      raise Error.new("#{name} does not match checksums.txt", 0) if Digest::SHA256.hexdigest(archive) != expected_hash(checksums, name)

      begin
        binary = os == "windows" ? from_zip(archive, exe) : from_tar(archive, exe)
      rescue Zlib::Error, Gem::Package::Error => e
        raise Error.new("could not read #{name}: #{e.message}", 0)
      end
      raise Error.new("#{name} has no #{exe}", 0) unless binary

      FileUtils.mkdir_p(dir)
      path = File.join(dir, exe)
      temp = "#{path}.#{Process.pid}.download"
      begin
        File.binwrite(temp, binary)
        File.chmod(0o755, temp)
        File.rename(temp, path)
      ensure
        FileUtils.rm_f(temp)
      end
      path
    end
  end
end
