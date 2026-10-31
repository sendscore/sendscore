defmodule SendScore.Binary do
  @moduledoc "Finds the CLI, and downloads a release when none is installed."

  alias SendScore.{Error, Hashes}

  @engine_version "0.3.0"
  @releases "https://github.com/sendscore/sendscore/releases/download"
  @max_download 100 * 1024 * 1024
  @download_timeout 120_000

  @doc "The CLI release this package downloads when none is installed."
  def engine_version, do: @engine_version

  @doc """
  Finds the CLI: SENDSCORE_BIN, then the pinned version on PATH, then the
  cache, then a download. A cached binary is checked against its pinned hash
  every time, so a file planted in the cache is replaced and never run.
  """
  @spec find() :: String.t()
  def find do
    case System.get_env("SENDSCORE_BIN") do
      value when value not in [nil, ""] -> value
      _ -> on_path() || cached_or_download()
    end
  end

  defp on_path do
    separator = if windows?(), do: ";", else: ":"
    name = if windows?(), do: "sendscore.exe", else: "sendscore"

    (System.get_env("PATH") || "")
    |> String.split(separator)
    |> Enum.filter(&(Path.type(&1) == :absolute))
    |> Enum.map(&Path.join(&1, name))
    |> Enum.find(&(executable?(&1) and right_version?(&1)))
  end

  defp windows?, do: match?({:win32, _}, :os.type())

  defp right_version?(path) do
    case execute(path, ["--version"], 10_000) do
      {0, output} ->
        output |> String.split() |> List.last("") |> String.trim_leading("v") == @engine_version

      _ ->
        false
    end
  rescue
    _ -> false
  end

  @doc """
  Runs a program directly, with no shell, and returns `{code, stdout}`, or
  `:timeout` once it has been killed.
  """
  def execute(binary, args, timeout) do
    port = Port.open({:spawn_executable, binary}, [:binary, :exit_status, :eof, :hide, args: args])
    deadline = if timeout, do: System.monotonic_time(:millisecond) + timeout
    collect(port, deadline, [], nil, false)
  end

  defp collect(port, _deadline, output, code, true) when is_integer(code) do
    Port.close(port)
    {if(code >= 128, do: Error.killed(), else: code), output |> Enum.reverse() |> IO.iodata_to_binary()}
  end

  defp collect(port, deadline, output, code, eof) do
    wait = if deadline, do: max(deadline - System.monotonic_time(:millisecond), 0), else: :infinity

    receive do
      {^port, {:data, data}} -> collect(port, deadline, [data | output], code, eof)
      {^port, {:exit_status, status}} -> collect(port, deadline, output, status, eof)
      {^port, :eof} -> collect(port, deadline, output, code, true)
    after
      wait ->
        kill(port)
        :timeout
    end
  end

  defp kill(port) do
    with {:os_pid, pid} <- Port.info(port, :os_pid) do
      if windows?() do
        System.cmd("taskkill", ["/F", "/PID", to_string(pid)], stderr_to_stdout: true)
      else
        System.cmd("kill", ["-9", to_string(pid)], stderr_to_stdout: true)
      end
    end

    Port.close(port)
  end

  defp cached_or_download do
    {os, _arch} = target = platform()
    pin = pin_for(target)
    dir = Path.join(cache_root(), @engine_version)
    path = Path.join(dir, exe(os))

    if matches_pin?(path, pin) do
      path
    else
      download(@engine_version, "#{@releases}/v#{@engine_version}", dir, pin, target)
    end
  end

  defp cache_root do
    root = :filename.basedir(:user_cache, ~c"sendscore") |> to_string()
    if Path.type(root) == :absolute, do: root, else: Path.join([System.user_home!(), ".cache", "sendscore"])
  end

  @doc "The `{archive, binary}` hashes of a platform. With none, nothing is trusted."
  def pin_for({os, arch}, pins \\ Hashes.pins()) do
    Map.get(pins, "#{os}_#{arch}") ||
      raise Error,
        message:
          "this package has no pinned hash for #{os}_#{arch}, so it will not download a CLI. " <>
            "Install the matching sendscore on PATH, or set SENDSCORE_BIN."
  end

  @doc "Whether a file exists and is exactly the pinned binary."
  def matches_pin?(path, {_archive, binary}) do
    case File.read(path) do
      {:ok, data} -> sha256(data) == binary
      _ -> false
    end
  end

  defp sha256(data), do: :crypto.hash(:sha256, data) |> Base.encode16(case: :lower)

  defp executable?(path) do
    case File.stat(path) do
      {:ok, %File.Stat{type: :regular, mode: mode}} -> windows?() or Bitwise.band(mode, 0o111) != 0
      _ -> false
    end
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
        String.starts_with?(arch, ["aarch64", "arm64"]) -> "arm64"
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

    http = [timeout: @download_timeout, autoredirect: true] ++ if String.starts_with?(url, "https"), do: [ssl: ssl], else: []

    case :httpc.request(:get, {String.to_charlist(url), []}, http, sync: false, stream: :self, body_format: :binary) do
      {:ok, request} -> receive_body(request, url, [], 0)
      {:error, reason} -> raise Error, message: "download of #{url} failed: #{inspect(reason)}"
    end
  end

  defp receive_body(request, url, parts, size) do
    receive do
      {:http, {^request, :stream_start, _headers}} ->
        receive_body(request, url, parts, size)

      {:http, {^request, :stream, part}} when size + byte_size(part) > @max_download ->
        :httpc.cancel_request(request)
        raise Error, message: "download of #{url} is too large"

      {:http, {^request, :stream, part}} ->
        receive_body(request, url, [part | parts], size + byte_size(part))

      {:http, {^request, :stream_end, _headers}} ->
        parts |> Enum.reverse() |> IO.iodata_to_binary()

      {:http, {^request, {{_, code, _}, _, _}}} ->
        raise Error, message: "download of #{url} answered #{code}"

      {:http, {^request, {:error, reason}}} ->
        raise Error, message: "download of #{url} failed: #{inspect(reason)}"
    after
      @download_timeout ->
        :httpc.cancel_request(request)
        raise Error, message: "download of #{url} timed out"
    end
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
  Downloads a release into `dir`, and returns the binary's path. The archive
  must match its pin before anything is extracted, and the binary must match
  its pin before it reaches the disk.
  """
  @spec download(String.t(), String.t(), Path.t(), {String.t(), String.t()}, {String.t(), String.t()}) :: String.t()
  def download(version, base, dir, {archive_hash, binary_hash}, {os, arch} \\ platform()) do
    exe = exe(os)
    ext = if os == "windows", do: "zip", else: "tar.gz"
    name = "sendscore_#{version}_#{os}_#{arch}.#{ext}"
    archive = fetch("#{base}/#{name}")

    if sha256(archive) != archive_hash do
      raise Error, message: "#{name} does not match its pinned hash"
    end

    binary = extract(archive, os, exe) || raise Error, message: "#{name} has no #{exe}"

    if sha256(binary) != binary_hash do
      raise Error, message: "the binary in #{name} does not match its pinned hash"
    end

    File.mkdir_p!(dir)
    path = Path.join(dir, exe)
    temp = "#{path}.#{System.unique_integer([:positive])}.#{Base.encode16(:crypto.strong_rand_bytes(6))}.download"

    try do
      File.write!(temp, binary)
      File.chmod!(temp, 0o755)
      File.rename!(temp, path)
    after
      File.rm(temp)
    end

    path
  end
end
