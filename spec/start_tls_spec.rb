# frozen_string_literal: true

require_relative 'spec_helper'

RSpec.describe StartTls do
  describe StartTls::Base do
    it 'upgrade is a no-op' do
      expect(StartTls::Base.upgrade(nil)).to be_nil
    end
  end

  describe StartTls::Ftp do
    let(:socket) { instance_double(Socket) }

    before do
      allow(socket).to receive(:puts)
    end

    describe '.read_response' do
      it 'accepts a single-line response with the expected code' do
        allow(socket).to receive(:gets).and_return("220 Ready\r\n")
        expect { StartTls::Ftp.read_response(socket, '220') }.not_to raise_error
      end

      it 'raises AppErr on an unexpected code' do
        allow(socket).to receive(:gets).and_return("530 Not logged in\r\n")
        expect { StartTls::Ftp.read_response(socket, '220') }.to raise_error(AppErr, /FTP Protocol Error/)
      end

      it 'raises AppErr when socket returns nil (connection closed)' do
        allow(socket).to receive(:gets).and_return(nil)
        expect { StartTls::Ftp.read_response(socket, '220') }.to raise_error(AppErr, /Didn't get a response/)
      end

      it 'handles multi-line responses' do
        responses = [
          "211-Features:\r\n",
          " AUTH TLS\r\n",
          " UTF8\r\n",
          "211 End\r\n"
        ]
        allow(socket).to receive(:gets).and_return(*responses)
        expect { StartTls::Ftp.read_response(socket, '211') }.not_to raise_error
      end
    end

    describe '.upgrade' do
      it 'completes the STARTTLS handshake sequence' do
        responses = [
          "220 FTP server ready\r\n",  # greeting
          "211-Features:\r\n",         # FEAT response (multiline)
          " AUTH TLS\r\n",
          "211 End\r\n",
          "234 AUTH TLS successful\r\n" # AUTH TLS response
        ]
        allow(socket).to receive(:gets).and_return(*responses)

        expect { StartTls::Ftp.upgrade(socket) }.not_to raise_error
        expect(socket).to have_received(:puts).with("FEAT\r\n")
        expect(socket).to have_received(:puts).with("AUTH TLS\r\n")
      end
    end
  end

  describe 'HANDSHAKERS' do
    it 'maps port 21 to the Ftp handshaker' do
      expect(StartTls::HANDSHAKERS[21]).to eq(StartTls::Ftp)
    end

    it 'maps port 990 to the Ftp handshaker' do
      expect(StartTls::HANDSHAKERS[990]).to eq(StartTls::Ftp)
    end

    it 'defaults to Base for unknown ports' do
      result = StartTls::HANDSHAKERS.fetch(443, StartTls::Base)
      expect(result).to eq(StartTls::Base)
    end
  end
end
