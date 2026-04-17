# frozen_string_literal: true

require_relative '../lib/cert_inspector'
require 'tempfile'
require 'stringio'

module CertTestHelpers
  def generate_key(bits = 2048)
    OpenSSL::PKey::RSA.new(bits)
  end

  # Builds a self-signed root CA certificate
  def build_root_ca(cn: 'Test Root CA', years: 5, key: nil)
    key ||= generate_key
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = rand(1..2**32)
    cert.subject = OpenSSL::X509::Name.parse("/CN=#{cn}")
    cert.issuer = cert.subject
    cert.not_before = Time.now - 60
    cert.not_after = Time.now + (years * 365 * 24 * 3600)
    cert.public_key = key.public_key

    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = cert
    ef.issuer_certificate = cert
    cert.add_extension(ef.create_extension('basicConstraints', 'CA:TRUE', true))
    cert.add_extension(ef.create_extension('subjectKeyIdentifier', 'hash'))

    cert.sign(key, OpenSSL::Digest.new('SHA256'))
    [cert, key]
  end

  # Builds a leaf certificate signed by the given CA
  def build_leaf(ca_cert:, ca_key:, cn: 'leaf.example.com', sans: nil, algorithm: 'SHA256')
    key = generate_key
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = rand(1..2**32)
    cert.subject = OpenSSL::X509::Name.parse("/CN=#{cn}")
    cert.issuer = ca_cert.subject
    cert.not_before = Time.now - 60
    cert.not_after = Time.now + (365 * 24 * 3600)
    cert.public_key = key.public_key

    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = cert
    ef.issuer_certificate = ca_cert

    if sans
      san_value = sans.map { |s| "DNS:#{s}" }.join(',')
      cert.add_extension(ef.create_extension('subjectAltName', san_value))
    end

    cert.sign(ca_key, OpenSSL::Digest.new(algorithm))
    [cert, key]
  end

  def pem_bundle(*certs)
    certs.map(&:to_pem).join("\n")
  end

  def write_pem_tempfile(*certs)
    file = Tempfile.new(['test_chain', '.pem'])
    file.write(pem_bundle(*certs))
    file.flush
    file
  end

  def capture_stdout(&block)
    old = $stdout
    $stdout = StringIO.new
    block.call
    $stdout.string
  ensure
    $stdout = old
  end
end

RSpec.configure do |config|
  config.include CertTestHelpers
end
