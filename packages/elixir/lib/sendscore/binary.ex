defmodule SendScore.Binary do
  @moduledoc "Finds the CLI, and downloads a release when none is installed."

  alias SendScore.Error

  @engine_version "0.2.0"
  @releases "https://github.com/sendscore/sendscore/releases/download"

  @doc "The CLI release this package downloads when none is installed."
  def engine_version, do: @engine_version

  @doc "Finds the CLI: SENDSCORE_BIN, then PATH, then the cache, then a download."
  @spec find() :: String.t()
  def find do
    case System.get_env("SENDSCORE_BIN") do
      value when value not in [nil, ""] -> value
      _ -> System.find_executable("sendscore") || cached_or_download()
    end
  end

  defp cached_or_download do
    {os, _arch} = target = platform()
    dir = Path.join([:filename.basedir(:user_cache, ~c"sendscore") |> to_string(), @engine_version])
    path = Path.join(dir, exe(os))

    if executable?(path) do
      path
    else
      download(@engine_version, "#{@releases}/v#{@engine_version}", dir, target)
    end
  end

  defp executable?(path) do
    match?({:ok, %File.Stat{type: :regular, mode: mode}} when Bitwise.band(mode, 0o111) != 0, File.stat(path))
  end

  defp exe("windows"), do: "sendscore.exe"
  defp exe(_), do: "sendscore"

  @doc false
  def platform do
    arch = :erlang.system_info(:system_architecture) |> to_string()

    os =
      cond do
        match?({:win32, _}, :os.type()) -> "windows"
        match?({:unix, :darwin}, :os.type()) -> "darwin"
        match?({:unix, :linux}, :os.type()) -> "linux"
        true -> raise Error, message: "no SendScore build for #{arch}"
      end

    cpu =
      cond do
        String.starts_with?(arch, ["x86_64", "amd64", "win32"]) -> "amd64"
        String.starts_with?(arch, ["aarch64", "arm64", "arm-"]) -> "arm64"
        true -> raise Error, message: "no SendScore build for #{arch}"
      end

    {os, cpu}
  end

  defp fetch(url) do
    {:ok, _} = Application.ensure_all_started(:inets)
    {:ok, _} = Application.ensure_all_started(:ssl)

    ssl = [
      verify: :verify_peer,
      cacerts: :public_key.cacerts_get(),
      customize_hostname_check: [match_fun: :public_key.pkix_verify_hostname_match_fun(:https)]
    ]

    http = [timeout: 60_000, autoredirect: true] ++ if String.starts_with?(url, "https"), do: [ssl: ssl], else: []

    case :httpc.request(:get, {String.to_charlist(url), []}, http, body_format: :binary) do
      {:ok, {{_, 200, _}, _, body}} -> body
      {:ok, {{_, code, _}, _, _}} -> raise Error, message: "download of #{url} answered #{code}"
      {:error, reason} -> raise Error, message: "download of #{url} failed: #{inspect(reason)}"
    end
  end

  defp expected_hash(checksums, name) do
    found =
      checksums
      |> String.split("\n", trim: true)
      |> Enum.find_value(fn line ->
        case String.split(line) do
          [hash, ^name] -> String.downcase(hash)
          _ -> nil
        end
      end)

    found || raise Error, message: "checksums.txt does not list #{name}"
  end

  # One file, by its exact name, read into memory, so no path in the archive
  # is ever used.
  defp extract(archive, "windows", exe) do
    case :zip.extract(archive, [:memory, {:file_list, [String.to_charlist(exe)]}]) do
      {:ok, [{_, data}]} -> data
      _ -> nil
    end
  end

  defp extract(archive, _os, exe) do
    case :erl_tar.extract({:binary, archive}, [:compressed, :memory, {:files, [String.to_charlist(exe)]}]) do
      {:ok, [{_, data}]} -> data
      _ -> nil
    end
  end

  @doc """
  Downloads a release into `dir`, and returns the binary's path. The archive is
  checked against checksums.txt before anything is extracted, so a binary that
  does not match never reaches the disk.
  """
  @spec download(String.t(), String.t(), Path.t(), {String.t(), String.t()}) :: String.t()
  def download(version, base, dir, {os, arch} \\ platform()) do
    exe = exe(os)
    ext = if os == "windows", do: "zip", else: "tar.gz"
    name = "sendscore_#{version}_#{os}_#{arch}.#{ext}"
    checksums = fetch("#{base}/checksums.txt")
    archive = fetch("#{base}/#{name}")
    actual = :crypto.hash(:sha256, archive) |> Base.encode16(case: :lower)

    if actual != expected_hash(checksums, name) do
      raise Error, message: "#{name} does not match checksums.txt"
    end

    binary = extract(archive, os, exe) || raise Error, message: "#{name} has no #{exe}"
    File.mkdir_p!(dir)
    path = Path.join(dir, exe)
    temp = "#{path}.#{System.unique_integer([:positive])}.download"
    File.write!(temp, binary)
    File.chmod!(temp, 0o755)
    File.rename!(temp, path)
    path
  end
end
