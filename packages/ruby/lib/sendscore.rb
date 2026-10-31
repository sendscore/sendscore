require "json"
require "open3"
require "sendscore/version"

# Checks newsletter emails with the SendScore CLI. Reports are the
# sendscore.verdict/v1 JSON as hashes with string keys, and new keys may
# appear. sig/sendscore.rbs has their types.
module SendScore
  # The CLI could not produce a report, or could not be found or installed.
  class Error < StandardError
    # The CLI's exit code: 64 and above, or 0 when the CLI never ran.
    attr_reader :exit_code

    def initialize(message, exit_code)
      super(message)
      @exit_code = exit_code
    end
  end

  module_function

  # Checks one message, given as a path, or as bytes with `bytes: true`. A
  # message that fails checks is still a report: this raises only when no
  # report could be made.
  def check(message, bytes: false, offline: false, links: false, ip: nil, mail_from: nil, helo: nil, tls: nil, previous: nil)
    args = %w[check --json]
    args << "--offline" if offline
    args << "--links" if links
    args.push("--ip", ip) unless ip.nil?
    args.push("--mail-from", mail_from) unless mail_from.nil?
    args.push("--helo", helo) unless helo.nil?
    args.push("--tls", tls ? "yes" : "no") unless tls.nil?
    args.push("--previous", previous.to_s) unless previous.nil?
    args.push("--", bytes ? "-" : message.to_s)
    run(args, bytes ? message : nil, [0, 1, 2])
  end

  # Compares two saved messages, given as paths.
  def diff(before, after)
    result = run(["diff", "--json", "--", before.to_s, after.to_s], nil, [0, 1])
    result["changes"] ||= []
    result
  end

  def run(args, stdin, verdict_codes)
    binary = Binary.find
    begin
      # A list of arguments runs the program directly, with no shell.
      stdout, stderr, status = Open3.capture3([binary, binary], *args, stdin_data: stdin || "", binmode: true)
    rescue SystemCallError => e
      raise Error.new("could not run #{binary}: #{e.message}", 0)
    end
    code = status.exitstatus
    unless verdict_codes.include?(code)
      text = stderr.strip
      raise Error.new(text.empty? ? "sendscore exited #{code}" : text, code)
    end
    begin
      JSON.parse(stdout)
    rescue JSON::ParserError
      raise Error.new("sendscore printed something that is not JSON", code)
    end
  end
  private_class_method :run
end

require "sendscore/binary"
