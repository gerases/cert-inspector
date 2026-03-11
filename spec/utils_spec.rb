# frozen_string_literal: true

require_relative 'spec_helper'

RSpec.describe Utils do
  describe '.divider' do
    it 'returns an 80-character line of dashes' do
      expect(Utils.divider).to eq('-' * 80)
      expect(Utils.divider.size).to eq(80)
    end
  end

  describe '.short_path' do
    it 'replaces the current working directory with a dot' do
      cwd = File.expand_path('.')
      full_path = "#{cwd}/lib/cert_inspector.rb"
      expect(Utils.short_path(full_path)).to eq('./lib/cert_inspector.rb')
    end

    it 'returns the path unchanged if it does not contain cwd' do
      expect(Utils.short_path('/other/path/file.rb')).to eq('/other/path/file.rb')
    end
  end

  describe '.trace' do
    it 'prints the error class and message' do
      err = begin
        raise AppErr, 'something broke'
      rescue StandardError => e
        e
      end

      output = capture_stdout { Utils.trace(err) }
      expect(output).to include('AppErr')
      expect(output).to include('something broke')
    end

    it 'respects the limit parameter' do
      err = begin
        raise AppErr, 'test'
      rescue StandardError => e
        e
      end

      output = capture_stdout { Utils.trace(err, limit: 1) }
      numbered_lines = output.lines.select { |l| l.match?(/^\s+\d+\./) }
      expect(numbered_lines.size).to eq(1)
    end
  end
end

RSpec.describe Processor do
  describe '.parse_uri' do
    it 'prepends https:// when no scheme is given' do
      allow(Resolv).to receive(:getaddress).and_return('93.184.216.34')
      uri = Processor.parse_uri('example.com')
      expect(uri.scheme).to eq('https')
      expect(uri.host).to eq('example.com')
    end

    it 'preserves an explicit scheme' do
      allow(Resolv).to receive(:getaddress).and_return('93.184.216.34')
      uri = Processor.parse_uri('ftp://ftp.example.com')
      expect(uri.scheme).to eq('ftp')
    end

    it 'raises AppErr when the host cannot be resolved' do
      allow(Resolv).to receive(:getaddress).and_raise(Resolv::ResolvError)
      expect { Processor.parse_uri('nonexistent.invalid') }.to raise_error(AppErr, /Can't resolve/)
    end

    it 'raises AppErr for an empty input (unresolvable empty host)' do
      expect { Processor.parse_uri('') }.to raise_error(AppErr, /Can't resolve/)
    end

    it 'returns nil for invalid URIs' do
      expect(Processor.parse_uri('ht tp://bad url')).to be_nil
    end
  end

  describe '.run' do
    let(:ca_cert_and_key) { build_root_ca }
    let(:ca_cert) { ca_cert_and_key[0] }
    let(:ca_key) { ca_cert_and_key[1] }

    it 'processes a PEM file' do
      leaf, = build_leaf(ca_cert: ca_cert, ca_key: ca_key)
      file = write_pem_tempfile(leaf, ca_cert)

      store = instance_double(OpenSSL::X509::Store)
      allow(OpenSSL::X509::Store).to receive(:new).and_return(store)
      allow(store).to receive(:set_default_paths).and_return(store)
      allow(store).to receive(:tap).and_yield(store).and_return(store)
      allow(store).to receive(:add_file)
      allow(store).to receive(:verify).and_return(true)

      output = capture_stdout { Processor.run(file.path) }
      expect(output).to include('Subject')
      expect(output).to include('VERIFY RESULT:')
    ensure
      file&.close!
    end
  end
end
