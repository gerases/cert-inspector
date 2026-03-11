# frozen_string_literal: true

require_relative 'spec_helper'

RSpec.describe Cert do
  let(:ca_cert_and_key) { build_root_ca }
  let(:ca_cert) { ca_cert_and_key[0] }
  let(:ca_key) { ca_cert_and_key[1] }

  describe '#weak_signature?' do
    it 'returns false for SHA256' do
      leaf, = build_leaf(ca_cert: ca_cert, ca_key: ca_key, algorithm: 'SHA256')
      expect(Cert.new(leaf).weak_signature?).to be false
    end

    it 'returns true for SHA1' do
      leaf, = build_leaf(ca_cert: ca_cert, ca_key: ca_key, algorithm: 'SHA1')
      expect(Cert.new(leaf).weak_signature?).to be true
    end
  end

  describe '#parsed_sans' do
    it 'returns an empty array when no SANs are present' do
      leaf, = build_leaf(ca_cert: ca_cert, ca_key: ca_key, sans: nil)
      expect(Cert.new(leaf).parsed_sans).to eq([])
    end

    it 'parses DNS SANs from the certificate' do
      sans = %w[foo.example.com bar.example.com]
      leaf, = build_leaf(ca_cert: ca_cert, ca_key: ca_key, sans: sans)
      expect(Cert.new(leaf).parsed_sans).to eq(sans)
    end

    it 'memoizes the result' do
      leaf, = build_leaf(ca_cert: ca_cert, ca_key: ca_key, sans: %w[a.test])
      cert = Cert.new(leaf)
      expect(cert.parsed_sans).to equal(cert.parsed_sans)
    end
  end

  describe '#validate' do
    it 'records no errors when host matches a SAN exactly' do
      leaf, = build_leaf(ca_cert: ca_cert, ca_key: ca_key, sans: %w[app.test])
      cert = Cert.new(leaf, host: 'app.test')
      expect(cert.errors).to be_empty
    end

    it 'records an error when host is not in the SANs' do
      leaf, = build_leaf(ca_cert: ca_cert, ca_key: ca_key, sans: %w[other.test])
      cert = Cert.new(leaf, host: 'app.test')
      expect(cert.errors).not_to be_empty
    end

    it 'skips validation when host is nil' do
      leaf, = build_leaf(ca_cert: ca_cert, ca_key: ca_key, sans: %w[other.test])
      cert = Cert.new(leaf)
      expect(cert.errors).to be_empty
    end

    it 'skips validation when there are no SANs' do
      leaf, = build_leaf(ca_cert: ca_cert, ca_key: ca_key, sans: nil)
      cert = Cert.new(leaf, host: 'anything.test')
      expect(cert.errors).to be_empty
    end
  end

  describe '#validate_wild_card' do
    it 'matches a wildcard SAN against the host' do
      leaf, = build_leaf(ca_cert: ca_cert, ca_key: ca_key, sans: %w[*.example.com])
      cert = Cert.new(leaf, host: 'app.example.com')
      expect(cert.errors).to be_empty
    end

    it 'does not match a wildcard against a deeper subdomain' do
      leaf, = build_leaf(ca_cert: ca_cert, ca_key: ca_key, sans: %w[*.example.com])
      cert = Cert.new(leaf, host: 'deep.sub.example.com')
      expect(cert.errors).not_to be_empty
    end

    it 'does not match a wildcard against the bare domain' do
      leaf, = build_leaf(ca_cert: ca_cert, ca_key: ca_key, sans: %w[*.example.com])
      cert = Cert.new(leaf, host: 'example.com')
      expect(cert.errors).not_to be_empty
    end
  end

  describe '#self_signed?' do
    it 'returns true when subject equals issuer' do
      cert = Cert.new(ca_cert)
      expect(cert.self_signed?).to be true
    end

    it 'returns false for a CA-signed leaf' do
      leaf, = build_leaf(ca_cert: ca_cert, ca_key: ca_key)
      cert = Cert.new(leaf)
      expect(cert.self_signed?).to be false
    end
  end

  describe '#dns_info' do
    it 'returns nil when there are no SANs' do
      leaf, = build_leaf(ca_cert: ca_cert, ca_key: ca_key, sans: nil)
      expect(Cert.new(leaf).dns_info).to be_nil
    end

    it 'shows all SANs when there are 2 or fewer' do
      leaf, = build_leaf(ca_cert: ca_cert, ca_key: ca_key, sans: %w[a.test b.test])
      expect(Cert.new(leaf).dns_info).to eq('a.test, b.test')
    end

    it 'truncates and shows count when there are more than 2' do
      leaf, = build_leaf(ca_cert: ca_cert, ca_key: ca_key, sans: %w[a.test b.test c.test d.test])
      info = Cert.new(leaf).dns_info
      expect(info).to include('a.test, b.test')
      expect(info).to include('2 more')
    end
  end

  describe '#show' do
    it 'prints certificate details to stdout' do
      leaf, = build_leaf(ca_cert: ca_cert, ca_key: ca_key, sans: %w[leaf.example.com])
      cert = Cert.new(leaf, host: 'leaf.example.com')
      output = capture_stdout { cert.show(1) }
      expect(output).to include('Subject')
      expect(output).to include('Issuer')
      expect(output).to include('Expires')
      expect(output).to include('Algorithm')
    end

    it 'truncates values longer than 80 characters with an indicator' do
      leaf, = build_leaf(ca_cert: ca_cert, ca_key: ca_key, sans: nil)
      cert = Cert.new(leaf)

      long_subject = 'X' * 100
      allow(leaf).to receive(:subject).and_return(long_subject)

      output = capture_stdout { cert.show(1) }
      lines = output.lines.select { |l| l.include?('Subject') }
      expect(lines.first).to include('...')
      expect(lines.first).not_to include('X' * 100)
    end
  end
end
