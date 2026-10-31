defmodule SendScore.Error do
  @moduledoc """
  The CLI could not produce a report, or could not be found or installed.

  `exit_code` is the CLI's, 64 and above, 0 when the CLI never ran, or -1 when
  it was killed or stopped by a timeout.
  """

  defexception [:message, exit_code: 0]

  @type t :: %__MODULE__{message: String.t(), exit_code: integer()}

  @doc false
  def killed, do: -1
end
