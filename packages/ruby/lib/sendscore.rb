require "json"
require "open3"
require "sendscore/version"

# Checks newsletter emails with the SendScore CLI. Reports are the
# sendscore.verdict/v1 JSON as hashes with string keys, and new keys may
# appear. sig/sendscore.rbs has their types.
module SendScore
  # The exit_code of a CLI that was killed, or stopped by a timeout.
  KILLED = -1

  # The CLI could not produce a report, or could not be found or installed.
  class Error < StandardError
    # The CLI's exit code: 64 and above, 0 when the CLI never ran, or KILLED.
    attr_reader :exit_code

    def initialize(message, exit_code)
      super(message)
      @exit_code = exit_code
    end
  end

  module_function

  # Checks one message, given as a path, or as bytes with `bytes: true`. A
  # message that fails checks is still a report: this raises only when no
  # report could be made. With a timeout in seconds, the CLI is killed when it
  # runs out.
  def check(message, bytes: false, offline: false, links: false, ip: nil, mail_from: nil, helo: nil, tls: nil, previous: nil, timeout: nil)
    args = %w[check --json]
    args << "--offline" if offline
    args << "--links" if links
    args.push("--ip", ip) unless ip.nil?
    args.push("--mail-from", mail_from) unless mail_from.nil?
    args.push("--helo", helo) unless helo.nil?
    args.push("--tls", tls ? "yes" : "no") unless tls.nil?
    args.push("--previous", path_arg(previous)) unless previous.nil?
    args.push("--", bytes ? "-" : path_arg(message))
    result = run(args, bytes ? message : nil, [0, 1, 2], timeout)
    raise Error.new("sendscore printed something that is not a verdict", 0) unless result["schema"].to_s.start_with?("sendscore.verdict/")

    result
  end

  # Compares two saved messages, given as paths.
  def diff(before, after, timeout: nil)
    result = run(["diff", "--json", "--", path_arg(before), path_arg(after)], nil, [0, 1], timeout)
    raise Error.new("sendscore printed something that is not a comparison", 0) unless result.key?("changes")

    result["changes"] ||= []
    result
  end

  # Runs a program with no shell, and kills it if timeout seconds pass. Not
  # part of the public API.
  def capture(binary, args, stdin, timeout)
    Open3.popen3([binary, binary], *args) do |input, output, errors, wait|
      [input, output, errors].each(&:binmode)
      stdout = Thread.new { output.read }
      stderr = Thread.new { errors.read }
      writer = Thread.new do
        begin
          input.write(stdin) if stdin
        rescue SystemCallError, IOError
          nil # The CLI stopped reading, and its exit code says why.
        ensure
          input.close unless input.closed?
        end
      end
      unless wait.join(timeout)
        Process.kill("KILL", wait.pid)
        wait.join
        writer.kill
        raise Error.new("sendscore did not finish within #{timeout} seconds", KILLED)
      end
      writer.join
      code = wait.value.exitstatus
      [code.nil? || code >= 128 ? KILLED : code, stdout.value, stderr.value]
    end
  rescue SystemCallError => e
    raise Error.new("could not run #{binary}: #{e.message}", 0)
  end

  # A lone "-" would mean standard input to the CLI.
  def path_arg(path)
    path.to_s == "-" ? "./-" : path.to_s
  end
  private_class_method :path_arg

  def run(args, stdin, verdict_codes, timeout)
    code, stdout, stderr = capture(Binary.find, args, stdin, timeout)
    unless verdict_codes.include?(code)
      text = stderr.strip
      raise Error.new(text.empty? ? "sendscore exited #{code}" : text, code)
    end
    begin
      result = JSON.parse(stdout)
    rescue JSON::ParserError
      raise Error.new("sendscore printed something that is not JSON", code)
    end
    raise Error.new("sendscore printed something that is not a report", code) unless result.is_a?(Hash)

    result
  end
  private_class_method :run
end

require "sendscore/binary"
