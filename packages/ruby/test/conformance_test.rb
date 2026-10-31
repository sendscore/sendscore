require "json"
require "minitest/autorun"
require "sendscore"

class ConformanceTest < Minitest::Test
  ROOT = File.expand_path("../../../conformance", __dir__)
  CASES = JSON.parse(File.read(File.join(ROOT, "cases.json")))["cases"]

  def path(rel)
    File.join(ROOT, rel)
  end

  def run_case(c)
    return SendScore.diff(path(c["before"]), path(c["after"])) if c["command"] == "diff"

    given = c.fetch("options", {})
    opts = { offline: true }
    %w[ip mail_from helo tls].each { |k| opts[k.to_sym] = given[k] if given.key?(k) }
    opts[:previous] = path(given["previous"]) if given.key?("previous")
    return SendScore.check(File.binread(path(c["message"])), bytes: true, **opts) if c["via"] == "stdin"

    SendScore.check(path(c["message"]), **opts)
  end

  CASES.each_with_index do |c, i|
    define_method("test_#{i}_#{c['name'].gsub(/\W+/, '_')}") do
      if c["exit"] > 2
        e = assert_raises(SendScore::Error) { run_case(c) }
        assert_equal c["exit"], e.exit_code
        next
      end
      got = run_case(c)
      changes = got["changes"] || []
      assert_equal c.fetch("changes", []), changes.map { |x| x["field"] }
      assert_equal c.fetch("worsened", []), changes.map { |x| x["worsened"] }.compact
      next if c["command"] == "diff"

      assert_equal c["verdict"], got["verdict"]
      assert_equal c["ready_to_send"], got["ready_to_send"]
      assert_equal c["checks"], got["checks"].map { |x| [x["id"], x["status"]] }.to_h
    end
  end
end
