defmodule SendScore.CliTest do
  # Sets process-wide environment, so it runs alone.
  use ExUnit.Case, async: false

  alias SendScore.Binary

  @repo Path.expand("../../..", __DIR__)
  @sample Path.join(@repo, "conformance/messages/clean.eml")
  @exe if match?({:win32, _}, :os.type()), do: "sendscore.exe", else: "sendscore"
  @keys ~w(SENDSCORE_BIN PATH HOME XDG_CACHE_HOME LOCALAPPDATA)

  setup_all do
    tmp = Path.join(System.tmp_dir!(), "sendscore-cli-#{System.unique_integer([:positive])}")
    built = Path.join([tmp, "built", @exe])
    {_, 0} = System.cmd("go", ["build", "-o", built, "./conformance/fakecli"], cd: @repo)
    on_exit(fn -> File.rm_rf!(tmp) end)
    {:ok, tmp: tmp, built: built}
  end

  setup do
    saved = Map.new(@keys, &{&1, System.get_env(&1)})

    on_exit(fn ->
      Enum.each(saved, fn
        {k, nil} -> System.delete_env(k)
        {k, v} -> System.put_env(k, v)
      end)
    end)
  end

  defp fake(ctx, mode) do
    path = Path.join([ctx.tmp, mode, @exe])
    File.mkdir_p!(Path.dirname(path))
    File.cp!(ctx.built, path)
    File.chmod!(path, 0o755)
    path
  end

  defp only_path(ctx, path) do
    System.delete_env("SENDSCORE_BIN")
    System.put_env("PATH", path)
    System.put_env("XDG_CACHE_HOME", Path.join(ctx.tmp, "cache"))
    System.put_env("LOCALAPPDATA", Path.join(ctx.tmp, "cache"))
  end

  test "a timeout kills the CLI", ctx do
    System.put_env("SENDSCORE_BIN", fake(ctx, "hang"))
    assert {:error, %{exit_code: -1}} = SendScore.check(@sample, timeout: 200)
    assert {:error, %{exit_code: -1}} = SendScore.diff(@sample, @sample, timeout: 200)
  end

  @tag skip: match?({:win32, _}, :os.type())
  test "a killed CLI has one exit code", ctx do
    System.put_env("SENDSCORE_BIN", fake(ctx, "killed"))
    assert {:error, %{exit_code: -1}} = SendScore.check(@sample)
  end

  test "output that is not a verdict is refused", ctx do
    System.put_env("SENDSCORE_BIN", fake(ctx, "planted"))
    assert {:error, _} = SendScore.check(@sample)
    assert {:error, _} = SendScore.diff(@sample, @sample)
  end

  test "unknown fields and stderr are tolerated", ctx do
    System.put_env("SENDSCORE_BIN", fake(ctx, "noisy"))
    assert {:ok, got} = SendScore.check(@sample)
    assert got["verdict"] == "pass"
    assert hd(got["checks"])["status"] == "brand_new"
  end

  test "a wrong version on PATH is not run", ctx do
    only_path(ctx, Path.dirname(fake(ctx, "version-9.9.9")))
    assert Binary.on_path() == nil
  end

  test "with no pins, nothing is installed" do
    assert_raise SendScore.Error, ~r/no pinned hash/, fn -> Binary.installed(%{}) end
  end

  test "the pinned version on PATH is used", ctx do
    path = fake(ctx, "version-#{Binary.engine_version()}")
    only_path(ctx, Path.dirname(path))
    assert Path.expand(Binary.find()) == Path.expand(path)
  end

  test "relative PATH entries are skipped", ctx do
    name = "version-#{Binary.engine_version()}"
    File.mkdir_p!(name)
    File.cp!(fake(ctx, name), Path.join(name, @exe))
    File.chmod!(Path.join(name, @exe), 0o755)
    on_exit(fn -> File.rm_rf!(name) end)
    separator = if match?({:win32, _}, :os.type()), do: ";", else: ":"
    only_path(ctx, separator <> name)
    assert Binary.on_path() == nil
  end

  test "paths that look like flags are files" do
    for name <- ["-", "-dash.eml"] do
      File.cp!(@sample, name)

      try do
        assert {:ok, got} = SendScore.check(name, offline: true)
        assert got["message"]["subject"] != ""
      after
        File.rm!(name)
      end
    end
  end
end
