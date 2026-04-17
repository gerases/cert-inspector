# frozen_string_literal: true

require_relative 'spec_helper'

RSpec.describe CertChain do
  let(:ca_cert_and_key) { build_root_ca }
  let(:ca_cert) { ca_cert_and_key[0] }
  let(:ca_key) { ca_cert_and_key[1] }
  let(:leaf) { build_leaf(ca_cert: ca_cert, ca_key: ca_key, sans: %w[leaf.example.com])[0] }

  describe '.decorators' do
    let(:leaf_cert) { Cert.new(leaf) }
    let(:ca_wrapper) { Cert.new(ca_cert) }

    it 'marks the first cert Subject with a space when not self-signed' do
      result = CertChain.decorators(2, leaf_cert, 1)
      expect(result['Subject']).to eq(' ')
    end

    it 'marks the last non-self-signed cert with └ for Subject only' do
      result = CertChain.decorators(2, leaf_cert, 2)
      expect(result['Subject']).to eq('└')
      expect(result['Issuer']).to be_nil
    end

    context 'with a self-signed certificate' do
      it 'uses ┌ for Subject when it is first in the chain' do
        result = CertChain.decorators(1, ca_wrapper, 1)
        expect(result['Subject']).to eq('┌')
        expect(result['Issuer']).to eq('└')
      end

      it 'uses ├ for Subject when it is not first' do
        result = CertChain.decorators(2, ca_wrapper, 2)
        expect(result['Subject']).to eq('├')
      end
    end
  end

  describe '#initialize' do
    it 'wraps raw certs into Cert objects' do
      cc = CertChain.new([leaf, ca_cert], host: 'leaf.example.com')
      expect(cc.wrapped_chain.size).to eq(2)
      expect(cc.wrapped_chain).to all(be_a(Cert))
    end

    it 'only sets host on the first (leaf) cert' do
      cc = CertChain.new([leaf, ca_cert], host: 'leaf.example.com')
      expect(cc.wrapped_chain[0].host).to eq('leaf.example.com')
      expect(cc.wrapped_chain[1].host).to be_nil
    end
  end

  describe '#show' do
    before do
      # Stub verify internals so we don't depend on the puppet CA file
      store = instance_double(OpenSSL::X509::Store)
      allow(OpenSSL::X509::Store).to receive(:new).and_return(store)
      allow(store).to receive(:set_default_paths).and_return(store)
      allow(store).to receive(:tap).and_yield(store).and_return(store)
      allow(store).to receive(:add_file)
      allow(store).to receive(:verify).and_return(true)
    end

    it 'prints all certificates and the verify result' do
      cc = CertChain.new([leaf, ca_cert], host: 'leaf.example.com', decorate: true)
      output = capture_stdout { cc.show }
      expect(output).to include('Subject')
      expect(output).to include('VERIFY RESULT:')
      expect(output).to include('TRUSTED and VALID')
    end

    it 'prints FAIL when verification fails' do
      store = instance_double(OpenSSL::X509::Store)
      allow(OpenSSL::X509::Store).to receive(:new).and_return(store)
      allow(store).to receive(:set_default_paths).and_return(store)
      allow(store).to receive(:tap).and_yield(store).and_return(store)
      allow(store).to receive(:add_file)
      allow(store).to receive(:verify).and_return(false)
      allow(store).to receive(:error_string).and_return('certificate has expired')

      cc = CertChain.new([leaf, ca_cert], host: 'leaf.example.com')
      output = capture_stdout { cc.show }
      expect(output).to include('certificate has expired')
    end
  end
end
