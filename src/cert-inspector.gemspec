# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name                  = 'cert-inspector'
  spec.version               = '1.0.0'
  spec.author                = 'Sergei Gerasenko'
  spec.homepage              = 'https://git.cnvrmedia.net/projects/SYSENG_RPMS/repos/rubygem-cert-inspector-rpm'
  spec.license               = 'Nonstandard'
  spec.email                 = 'sergei.gerasenko@epsilon.com'
  spec.metadata['rubygems_mfa_required'] = 'true'
  spec.files = Dir['lib/**/*', 'spec/**/*', '.rubocop.yml']
  spec.required_ruby_version = '>= 3.1.0'
  spec.summary               = 'A utility for inspecting x509 certificates'
  spec.description           = <<-DESC
    A utility for inspecting x509 certificates
  DESC
end
