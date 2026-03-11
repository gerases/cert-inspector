# frozen_string_literal: true

require 'net/http'
require 'openssl'
require 'resolv'

module StartTls
  # Base Handshaker (The "Null" Object -- do nothing)
  class Base
    def self.upgrade(_); end
  end

  # Example FTP conversation:
  # Server: 220 10.110.149.30 FTP server ready
  # Client: FEAT
  # Server: 211-Features:
  # AUTH TLS
  # ...
  # UTF8
  # 211 End
  # Client: AUTH TLS
  # Server: 234 AUTH TLS successful
  class Ftp < Base
    def self.upgrade(socket)
      # Read the greeting
      read_response(socket, '220')
      # Ask for the features
      send(socket, "FEAT\r\n")
      # Read response
      read_response(socket, '211')
      # Start TLS
      send(socket, "AUTH TLS\r\n")
      # Read response
      read_response(socket, '234')
    end

    def self.send(socket, text)
      warn "Client: #{text}"
      socket.puts(text)
    end

    def self.read_response(socket, expected_code)
      is_multiline = false

      loop do
        line = fetch_line(socket)
        warn "Server: #{line}"

        raise AppErr, "Didn't get a response" unless line

        # Check if this is the very first line of the response
        unless is_multiline || line.start_with?(expected_code)
          raise AppErr, "FTP Protocol Error: Expected #{expected_code}, got #{line}"
        end

        # Determine if we are entering or staying in a multi-line block
        # (Check index 3 for the hyphen on the very first line)
        is_multiline = true if line[3] == '-'

        # Termination condition:
        # Code + Space (e.g., "211 ") means the response is finished.
        break if line.start_with?("#{expected_code} ")

        # If it wasn't multi-line to begin with, and we checked the code, we are done.
        break unless is_multiline
      end
    end

    def self.fetch_line(socket)
      raw = socket.gets
      raw&.chomp
    end
  end

  HANDSHAKERS = {
    21 => StartTls::Ftp,
    990 => StartTls::Ftp
  }.freeze
end

# Module for miscellaneous utils
module Utils
  def self.divider
    '-' * 80
  end

  def self.short_path(path)
    project_root = File.expand_path('.')
    path.gsub(project_root, '.')
  end

  def self.trace(stack, limit: nil)
    separator = ('-' * 60).bold.red
    puts separator,
         "ERROR:   #{stack.class}".bold.red,
         "MESSAGE: #{stack.message}".yellow,
         separator
    trace = stack.backtrace
    lines = trace || []
    lines = lines.first(limit) if limit
    lines.each_with_index do |line, index|
      short_path = short_path(line)
      # Right-align the index for a clean list
      puts "  #{(index + 1).to_s.rjust(2)}. #{short_path}"
    end
  end
end

# Custom exception class to wrap issues in
class AppErr < StandardError; end

COLORS = {
  black: 30,
  red: 31,
  green: 32,
  yellow: 33,
  blue: 34,
  magenta: 35,
  cyan: 36,
  white: 37,
  bold: 1
}.freeze

def colorize(color, str = '')
  "\x1b[#{color}m#{str}\x1b[0m"
end

# Monkey patch the String class
class String
  COLORS.each do |color, code|
    define_method color do
      if $stdout.tty?
        "\x1b[#{code}m#{self}\x1b[0m"
      else
        self
      end
    end
  end
end

# A wrapper class for an actual SSL x509 object
class Cert
  WEAK_ALGORITHMS = /md5|sha1/i.freeze

  attr_reader :cert, :host, :errors

  def initialize(cert, host: nil)
    @cert = cert
    @host = host
    @errors = []
    validate
  end

  def weak_signature?
    # OpenSSL's signature_algorithm usually returns strings like "sha256WithRSAEncryption"
    cert.signature_algorithm.match?(WEAK_ALGORITHMS)
  end

  def signature_status
    weak_signature? ? 'WEAK (Legacy)'.bold.red : 'Strong'.green
  end

  # 1. Parse ONCE and remember the result
  def parsed_sans
    @parsed_sans ||= begin
      san_ext = cert.extensions.find { |ext| ext.oid == 'subjectAltName' }
      if san_ext
        san_ext.value.split(/,\s*/).map { |s| s.sub('DNS:', '') }
      else
        []
      end
    end
  end

  def validate
    return unless host
    return unless parsed_sans.any?
    return if parsed_sans.include?(host)
    return if validate_wild_card

    @errors << ["expected #{host} to be in #{parsed_sans.join(', ')}"]
  end

  def dns_info
    return nil if parsed_sans.empty?

    max_to_show = 2
    num_entries = parsed_sans.size
    info = parsed_sans.take(max_to_show).join(', ')
    if num_entries > max_to_show
      more = num_entries - max_to_show
      info += " ... and #{more} more".yellow
    end

    info
  end

  def self_signed?
    @self_signed ||= cert.subject == cert.issuer
  end

  def show(index, symbols = {})
    info = {
      'Subject' => cert.subject,
      'Issuer' => cert.issuer,
      'Starts' => cert.not_before,
      'Expires' => cert.not_after,
      'Serial' => format('%X', cert.serial),
      'Algorithm' => "#{cert.signature_algorithm} [#{signature_status}]"
    }

    info['DNS'] = dns_info if dns_info
    errors.empty? || info['Errors'] = errors.join("\n").bold.red
    max_width = info.transform_keys(&:yellow).keys.map(&:size).max || 0

    level2color = Hash.new(:white)
    level2color[1] = :cyan
    level2color[2] = :magenta
    level2color[3] = :yellow

    info.each do |key, val|
      symbol = symbols[key] || ' '
      key_s = key.yellow
      index_c = index.to_s.send(level2color[index])
      puts "#{symbol} [#{index_c}] #{key_s.ljust(max_width)}: #{val.to_s[0..79]}"
    end
  end

  def validate_wild_card
    host_parts = host.split('.')
    return false if host_parts.size < 2

    domain = host_parts[1..].join('.')
    parsed_sans.each do |san|
      return true if san.start_with?('*.') && domain == san[2..]
    end

    false
  end
end

# Class for representing a pem bundle on disk
class FileChain
  attr_reader :path, :chain

  def initialize(path)
    data = File.read(path)
    @chain = []
    pem_blocks = data.scan(/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m)
    pem_blocks.each do |block|
      cert = OpenSSL::X509::Certificate.new(block)
      @chain << cert
    end
  rescue AppErr, OpenSSL::X509::CertificateError => e
    abort "Couldn't read #{path}: #{e}".red.bold
  end
end

# Class for representing a pem bundle on the wire
class NetChain
  attr_reader :chain, :host, :errors

  def initialize(uri, timeout: 5)
    @errors = []
    @host = uri.host
    port = uri.port
    tcp_socket = Socket.tcp(@host, port, connect_timeout: timeout)

    # Pick the right handshaker based on port, or default to doing nothing (Base)
    handshaker = StartTls::HANDSHAKERS.fetch(port, StartTls::Base)

    begin
      Timeout.timeout(timeout) do
        handshaker.upgrade(tcp_socket)
      end
    rescue Timeout::ExitException
      raise AppErr, 'Timed out waiting for FTP greeting'
    end

    # Proceed with TLS wrap as usual
    ctx = OpenSSL::SSL::SSLContext.new
    @ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_socket, ctx)
    @ssl_socket.hostname = @host
    @ssl_socket.connect

    @chain = @ssl_socket.peer_cert_chain
  rescue Errno::ETIMEDOUT, Errno::ECONNREFUSED, SocketError => e
    raise AppErr, "Connection failed for #{uri}: #{e.message}"
  rescue OpenSSL::SSL::SSLError => e
    raise AppErr, "Can't connect to #{uri}: #{e}"
  end
end

# class for representing a chain of certificates
class CertChain
  attr_reader :wrapped_chain, :host, :chain

  def self.decorators(chain_size, cert, seq)
    is_first = (seq == 1)
    is_last  = (seq == chain_size)

    result = Hash.new('│')
    result['Issuer'] = '┌'

    result = {} if is_last
    result['Subject'] = '└'

    if cert.self_signed?
      result['Issuer'] = '└'
      result['Subject'] = if is_first
                            '┌'
                          else
                            '├'
                          end
    elsif is_first
      result['Subject'] = ' '
    end

    result
  end

  def initialize(chain, host: nil, **options)
    @host = host
    @chain = chain
    @options = options
    @wrapped_chain = chain.each.with_index(1).map do |cert, level|
      Cert.new(cert, host: level == 1 ? host : nil)
    end
  end

  def show
    wrapped_chain.each.with_index(1) do |cert, i|
      decorators = if @options[:decorate]
                     CertChain.decorators(wrapped_chain.size, cert, i)
                   else
                     {}
                   end
      cert.show(i, decorators)
    end

    verify_result, msg = verify
    verify_result = if verify_result == :ok
                      msg.green
                    else
                      msg.bold.red
                    end
    div = Utils.divider
    puts div, ['VERIFY RESULT:'.bold.white, verify_result].join(' '), div
  end

  private

  def verify
    store = OpenSSL::X509::Store.new.tap(&:set_default_paths)
    store.add_file('/etc/puppetlabs/puppet/ssl/certs/ca.pem')
    store_error = check_store(store)

    all_errors = (wrapped_chain[0].errors + [store_error]).compact
    return [:ok, 'TRUSTED and VALID'] if all_errors.empty?

    [:fail, all_errors.join("\n")]
  end

  def check_store(store)
    leaf = wrapped_chain[0].cert
    intermediates = wrapped_chain[1..].map(&:cert)
    store.verify(leaf, intermediates) ? nil : store.error_string
  end
end

# Factory class for initiating the functionality
class Processor
  def self.run(target)
    if File.exist?(target)
      chain = FileChain.new(target).chain
      host = nil
    elsif (uri = parse_uri(target))
      chain = NetChain.new(uri).chain
      host = uri.host
    else
      abort "Can't parse '#{target}' as a URL or a valid file name".red.bold
    end
    CertChain.new(chain, host: host, decorate: true).show
  end

  def self.parse_uri(input)
    url_candidate = input.match?(%r{^\w+://}) ? input : "https://#{input}"
    uri = URI.parse(url_candidate)
    host = uri.host
    return false unless host

    Resolv.getaddress(host)

    uri
  rescue Resolv::ResolvError
    raise AppErr, "Can't resolve #{host}"
  rescue URI::InvalidURIError
    nil
  end
end
