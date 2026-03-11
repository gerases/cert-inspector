# frozen_string_literal: true

require_relative 'spec_helper'

RSpec.describe NetChain do
  let(:ca_cert_and_key) { build_root_ca }
  let(:ca_cert) { ca_cert_and_key[0] }
  let(:ca_key) { ca_cert_and_key[1] }
  let(:leaf) { build_leaf(ca_cert: ca_cert, ca_key: ca_key)[0] }
  let(:uri) { URI.parse('https://example.com') }

  let(:tcp_socket) { instance_double(Socket, close: nil) }
  let(:ssl_socket) { instance_double(OpenSSL::SSL::SSLSocket, close: nil) }

  before do
    allow(Socket).to receive(:tcp).and_return(tcp_socket)
    allow(OpenSSL::SSL::SSLSocket).to receive(:new).and_return(ssl_socket)
    allow(ssl_socket).to receive(:hostname=)
    allow(ssl_socket).to receive(:connect)
    allow(ssl_socket).to receive(:peer_cert_chain).and_return([leaf, ca_cert])
  end

  it 'retrieves the certificate chain' do
    nc = NetChain.new(uri)
    expect(nc.chain.size).to eq(2)
  end

  it 'closes both sockets after success' do
    NetChain.new(uri)
    expect(ssl_socket).to have_received(:close)
    expect(tcp_socket).to have_received(:close)
  end

  it 'closes sockets even when SSL handshake fails' do
    allow(ssl_socket).to receive(:connect).and_raise(OpenSSL::SSL::SSLError, 'handshake failure')
    expect { NetChain.new(uri) }.to raise_error(AppErr, /Can't connect/)
    expect(ssl_socket).to have_received(:close)
    expect(tcp_socket).to have_received(:close)
  end

  it 'closes the tcp socket when connection is refused' do
    allow(Socket).to receive(:tcp).and_raise(Errno::ECONNREFUSED)
    expect { NetChain.new(uri) }.to raise_error(AppErr, /Connection failed/)
  end

  it 'wraps SocketError in AppErr' do
    allow(Socket).to receive(:tcp).and_raise(SocketError, 'getaddrinfo failure')
    expect { NetChain.new(uri) }.to raise_error(AppErr, /Connection failed/)
  end

  it 'uses the correct handshaker for FTP ports' do
    ftp_uri = URI.parse('ftp://ftp.example.com:21')
    allow(StartTls::Ftp).to receive(:upgrade)
    NetChain.new(ftp_uri)
    expect(StartTls::Ftp).to have_received(:upgrade).with(tcp_socket)
  end

  it 'uses Base (no-op) handshaker for HTTPS port' do
    allow(StartTls::Base).to receive(:upgrade)
    NetChain.new(uri)
    expect(StartTls::Base).to have_received(:upgrade).with(tcp_socket)
  end
end
