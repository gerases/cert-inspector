# frozen_string_literal: true

require_relative 'spec_helper'

RSpec.describe FileChain do
  let(:ca_cert_and_key) { build_root_ca }
  let(:ca_cert) { ca_cert_and_key[0] }
  let(:ca_key) { ca_cert_and_key[1] }

  it 'reads a single certificate from a PEM file' do
    file = write_pem_tempfile(ca_cert)
    chain = FileChain.new(file.path).chain
    expect(chain.size).to eq(1)
    expect(chain[0].subject.to_s).to eq(ca_cert.subject.to_s)
  ensure
    file&.close!
  end

  it 'reads multiple certificates from a PEM bundle' do
    leaf, = build_leaf(ca_cert: ca_cert, ca_key: ca_key)
    file = write_pem_tempfile(leaf, ca_cert)
    chain = FileChain.new(file.path).chain
    expect(chain.size).to eq(2)
  ensure
    file&.close!
  end

  it 'returns an empty chain when file has no PEM blocks' do
    file = Tempfile.new(['bad', '.pem'])
    file.write('not a certificate')
    file.flush
    chain = FileChain.new(file.path).chain
    expect(chain).to be_empty
  ensure
    file&.close!
  end

  it 'aborts on a corrupted PEM block' do
    file = Tempfile.new(['corrupt', '.pem'])
    file.write("-----BEGIN CERTIFICATE-----\ngarbage\n-----END CERTIFICATE-----\n")
    file.flush
    expect { FileChain.new(file.path) }.to raise_error(SystemExit)
  ensure
    file&.close!
  end
end
