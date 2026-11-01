defmodule SendScore.MixProject do
  use Mix.Project

  @version "0.3.1"

  def project do
    [
      app: :sendscore,
      version: @version,
      elixir: "~> 1.18",
      deps: [],
      description: "Check a newsletter email before it goes out. A typed wrapper around the SendScore CLI.",
      package: [
        licenses: ["MIT"],
        links: %{"GitHub" => "https://github.com/sendscore/sendscore"},
        files: ~w(lib mix.exs README.md LICENSE)
      ]
    ]
  end

  def application do
    [extra_applications: [:crypto, :inets, :logger, :public_key, :ssl]]
  end
end
