require "fileutils"
require "minitest/autorun"
require "sendscore"
require "tmpdir"

class CliTest < Minitest::Test
  REPO = File.expand_path("../../..", __dir__)
  SAMPLE = File.join(REPO, "conformance", "messages", "clean.eml")
  EXE = SendScore::Binary.windows? ? "sendscore.exe" : "sendscore"
  KEYS = %w[SENDSCORE_BIN PATH HOME XDG_CACHE_HOME LOCALAPPDATA].freeze
  TMP = Dir.mktmpdir("sendscore-cli-")
  BUILT = File.join(TMP, "built", EXE)
  system("go", "build", "-o", BUILT, "./conformance/fakecli", chdir: REPO, exception: true)
  Minitest.after_run { FileUtils.rm_rf(TMP) }

  def setup
    @saved = KEYS.map { |k| [k, ENV[k]] }.to_h
  end

  def teardown
    @saved.each { |k, v| ENV[k] = v }
  end

  def fake(mode)
    dir = File.join(TMP, mode)
    FileUtils.mkdir_p(dir)
    FileUtils.cp(BUILT, File.join(dir, EXE))
    File.join(dir, EXE)
  end

  def only_path(path)
    ENV.delete("SENDSCORE_BIN")
    ENV["PATH"] = path
    ENV["XDG_CACHE_HOME"] = ENV["LOCALAPPDATA"] = File.join(TMP, "cache")
  end

  def test_a_timeout_kills_the_cli
    ENV["SENDSCORE_BIN"] = fake("hang")
    e = assert_raises(SendScore::Error) { SendScore.check(SAMPLE, timeout: 0.2) }
    assert_equal SendScore::KILLED, e.exit_code
    e = assert_raises(SendScore::Error) { SendScore.diff(SAMPLE, SAMPLE, timeout: 0.2) }
    assert_equal SendScore::KILLED, e.exit_code
  end

  def test_a_killed_cli_has_one_exit_code
    skip "no signals" if SendScore::Binary.windows?
    ENV["SENDSCORE_BIN"] = fake("killed")
    e = assert_raises(SendScore::Error) { SendScore.check(SAMPLE) }
    assert_equal SendScore::KILLED, e.exit_code
  end

  def test_output_that_is_not_a_verdict_is_refused
    ENV["SENDSCORE_BIN"] = fake("planted")
    assert_raises(SendScore::Error) { SendScore.check(SAMPLE) }
    assert_raises(SendScore::Error) { SendScore.diff(SAMPLE, SAMPLE) }
  end

  def test_unknown_fields_and_stderr_are_tolerated
    ENV["SENDSCORE_BIN"] = fake("noisy")
    got = SendScore.check(SAMPLE)
    assert_equal "pass", got["verdict"]
    assert_equal "brand_new", got["checks"][0]["status"]
  end

  def test_a_wrong_version_on_path_is_not_run
    fake("version-9.9.9")
    only_path(File.join(TMP, "version-9.9.9"))
    assert_nil SendScore::Binary.on_path
  end

  def test_with_no_pins_nothing_is_installed
    assert_match(/no pinned hash/, assert_raises(SendScore::Error) { SendScore::Binary.installed({}) }.message)
  end

  def test_the_pinned_version_on_path_is_used
    path = fake("version-#{SendScore::ENGINE_VERSION}")
    only_path(File.dirname(path))
    assert_equal path, SendScore::Binary.find
  end

  def test_relative_path_entries_are_skipped
    name = "version-#{SendScore::ENGINE_VERSION}"
    FileUtils.mkdir_p(name)
    FileUtils.cp(fake(name), File.join(name, EXE))
    only_path([name, ""].join(File::PATH_SEPARATOR))
    assert_nil SendScore::Binary.on_path
  ensure
    FileUtils.rm_rf(name)
  end

  def test_paths_that_look_like_flags_are_files
    %w[- -dash.eml].each do |name|
      FileUtils.cp(SAMPLE, name)
      begin
        refute_empty SendScore.check(name, offline: true)["message"]["subject"]
      ensure
        FileUtils.rm_f(name)
      end
    end
  end
end
