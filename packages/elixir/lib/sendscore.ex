defmodule SendScore do
  @moduledoc """
  Checks newsletter emails with the SendScore CLI.

  Reports are the `sendscore.verdict/v1` JSON as maps with string keys, and new
  keys may appear. A message that fails checks is still a report, so `check/2`
  returns `{:ok, verdict}` for it. `{:error, %SendScore.Error{}}` means no
  report could be made.
  """

  alias SendScore.{Binary, Error}

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

  @doc """
  Checks one message, given as a path, or as `{:bytes, data}`.

  Erlang ports cannot close a program's standard input on their own, so bytes
  go to a private temporary file that is deleted afterwards, not through
  standard input as in the other packages.
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
    run(["check", "--json"] ++ flags(options) ++ ["--", path], [0, 1, 2])
  end

  @doc "Compares two saved messages, given as paths."
  @spec diff(Path.t(), Path.t()) :: {:ok, diff_result()} | {:error, Error.t()}
  def diff(before, later) do
    with {:ok, result} <- run(["diff", "--json", "--", before, later], [0, 1]) do
      {:ok, Map.update(result, "changes", [], &(&1 || []))}
    end
  end

  defp random, do: :crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)

  defp flags(options) do
    Enum.flat_map(options, fn
      {:offline, true} -> ["--offline"]
      {:links, true} -> ["--links"]
      {:ip, value} -> ["--ip", value]
      {:mail_from, value} -> ["--mail-from", value]
      {:helo, value} -> ["--helo", value]
      {:tls, value} when is_boolean(value) -> ["--tls", if(value, do: "yes", else: "no")]
      {:previous, value} -> ["--previous", value]
      _ -> []
    end)
  end

  defp run(args, verdict_codes) do
    binary = Binary.find()
    # System.cmd runs the program directly, with no shell. A verdict prints
    # nothing on stderr, so the merged output is the JSON or the error.
    {output, code} = System.cmd(binary, args, stderr_to_stdout: true)

    cond do
      code not in verdict_codes ->
        text = String.trim(output)
        {:error, %Error{message: if(text == "", do: "sendscore exited #{code}", else: text), exit_code: code}}

      true ->
        case JSON.decode(output) do
          {:ok, result} when is_map(result) -> {:ok, result}
          _ -> {:error, %Error{message: "sendscore printed something that is not JSON", exit_code: code}}
        end
    end
  rescue
    e in [Error, ErlangError, ArgumentError] -> {:error, %Error{message: Exception.message(e)}}
  end
end
