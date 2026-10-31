defmodule SendScore.Error do
  @moduledoc """
  The CLI could not produce a report, or could not be found or installed.

  `exit_code` is the CLI's, 64 and above, or 0 when the CLI never ran.
  """

  defexception [:message, exit_code: 0]

  @type t :: %__MODULE__{message: String.t(), exit_code: integer()}
end
