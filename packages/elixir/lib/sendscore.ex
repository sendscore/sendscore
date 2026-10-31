defmodule SendScore do
  @moduledoc """
  Checks newsletter emails with the SendScore CLI.

  Reports are the `sendscore.verdict/v1` JSON as maps with string keys, and new
  keys may appear. A message that fails checks is still a report, so `check/2`
  returns `{:ok, verdict}` for it. `{:error, %SendScore.Error{}}` means no
  report could be made.

  Erlang ports cannot capture stderr on its own, so the CLI's stderr goes to
  this program's stderr, and an error's message names only the exit code.
  """

  alias SendScore.{Binary, Error}

  @doc "The `exit_code` of a CLI that was killed, or stopped by a timeout."
  def killed, do: Error.killed()

  @type status :: String.t()
  @type check :: %{required(String.t()) => term()}
  @type verdict :: %{required(String.t()) => term()}
  @type diff_result :: %{required(String.t()) => term()}
  @type option ::
          {:offline, boolean()}
          | {:links, boolean()}
          | {:ip, String.t()}
          | {:mail_from, String.t()}
          | {:helo, String.t()}
          | {:tls, boolean()}
          | {:previous, Path.t()}
          | {:timeout, non_neg_integer()}

  @doc """
  Checks one message, given as a path, or as `{:bytes, data}`.

  Erlang ports cannot close a program's standard input on their own, so bytes
  go to a private temporary file that is deleted afterwards, not through
  standard input as in the other packages. `timeout:` is in milliseconds, and
  the CLI is killed when it runs out.
  """
  @spec check(Path.t() | {:bytes, binary()}, [option()]) :: {:ok, verdict()} | {:error, Error.t()}
  def check(message, options \\ [])

  def check({:bytes, data}, options) do
    path = Path.join(System.tmp_dir!(), "sendscore-#{System.unique_integer([:positive])}-#{random()}.eml")

    with :ok <- File.touch(path),
         :ok <- File.chmod(path, 0o600),
         :ok <- File.write(path, data) do
      try do
        check(path, options)
      after
        File.rm(path)
      end
    else
      {:error, reason} -> {:error, %Error{message: "could not write a temporary file: #{reason}"}}
    end
  end

  def check(path, options) when is_binary(path) do
    args = ["check", "--json"] ++ flags(options) ++ ["--", path_arg(path)]

    with {:ok, result} <- run(args, [0, 1, 2], options[:timeout]) do
      if String.starts_with?(to_string(result["schema"]), "sendscore.verdict/") do
        {:ok, result}
      else
        {:error, %Error{message: "sendscore printed something that is not a verdict"}}
      end
    end
  end

  @doc "Compares two saved messages, given as paths. `timeout:` is in milliseconds."
  @spec diff(Path.t(), Path.t(), timeout: non_neg_integer()) :: {:ok, diff_result()} | {:error, Error.t()}
  def diff(before, later, options \\ []) do
    args = ["diff", "--json", "--", path_arg(before), path_arg(later)]

    with {:ok, result} <- run(args, [0, 1], options[:timeout]) do
      if Map.has_key?(result, "changes") do
        {:ok, Map.update!(result, "changes", &(&1 || []))}
      else
        {:error, %Error{message: "sendscore printed something that is not a comparison"}}
      end
    end
  end

  # A lone "-" would mean standard input to the CLI.
  defp path_arg("-"), do: "./-"
  defp path_arg(path), do: path

  defp random, do: :crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)

  defp flags(options) do
    Enum.flat_map(options, fn
      {:offline, true} -> ["--offline"]
      {:links, true} -> ["--links"]
      {:ip, value} -> ["--ip", value]
      {:mail_from, value} -> ["--mail-from", value]
      {:helo, value} -> ["--helo", value]
      {:tls, value} when is_boolean(value) -> ["--tls", if(value, do: "yes", else: "no")]
      {:previous, value} -> ["--previous", path_arg(value)]
      _ -> []
    end)
  end

  defp run(args, verdict_codes, timeout) do
    binary = Binary.find()

    case Binary.execute(binary, args, timeout) do
      :timeout ->
        {:error, %Error{message: "sendscore did not finish within #{timeout} ms", exit_code: Error.killed()}}

      {code, output} ->
        if code in verdict_codes do
          decode(output, code)
        else
          {:error, %Error{message: "sendscore exited #{code}", exit_code: code}}
        end
    end
  rescue
    e in Error -> {:error, e}
    e -> {:error, %Error{message: Exception.message(e)}}
  end

  defp decode(output, code) do
    case JSON.decode(output) do
      {:ok, result} when is_map(result) -> {:ok, result}
      _ -> {:error, %Error{message: "sendscore printed something that is not JSON", exit_code: code}}
    end
  end
end
