require_relative "lib/sendscore/version"

Gem::Specification.new do |s|
  s.name = "sendscore"
  s.version = SendScore::VERSION
  s.summary = "Check a newsletter email before it goes out."
  s.description = "A typed wrapper around the SendScore CLI."
  s.authors = ["SendScore"]
  s.license = "MIT"
  s.homepage = "https://github.com/sendscore/sendscore"
  s.required_ruby_version = ">= 2.6"
  s.files = Dir["lib/**/*.rb", "sig/**/*.rbs", "README.md", "LICENSE"]
end
