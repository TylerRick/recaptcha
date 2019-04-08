# frozen_string_literal: true

require 'json'
require 'recaptcha/verify/verify_response'
require 'recaptcha/verify/verify_result'

module Recaptcha
  module Verify
    class << self
      def get(request_hash, options)
        recaptcha_logger.debug %(Calling Recaptcha::Verify.get(#{request_hash.inspect}))
        http = if Recaptcha.configuration.proxy
          proxy_server = URI.parse(Recaptcha.configuration.proxy)
          Net::HTTP::Proxy(proxy_server.host, proxy_server.port, proxy_server.user, proxy_server.password)
        else
          Net::HTTP
        end
        query = URI.encode_www_form(request_hash)
        uri = URI.parse(Recaptcha.configuration.verify_url + '?' + query)
        http_instance = http.new(uri.host, uri.port)
        http_instance.read_timeout = http_instance.open_timeout = options[:timeout] || DEFAULT_TIMEOUT
        http_instance.use_ssl = true if uri.port == 443
        request = Net::HTTP::Get.new(uri.request_uri)
        http_response = http_instance.request(request)
        response = VerifyResponse.new(http_response)
        recaptcha_logger.debug %(Response JSON: #{response.json})
        response
      end

      def recaptcha_logger
        Recaptcha.configuration.logger
      end
    end

    G_RESPONSE_LIMIT = 4000

    attr_reader :recaptcha_verify_result

    # Handles per-env skip, error handling, flash.
    def _verify_recaptcha(version, response_token, options = {})
      return true if Recaptcha::Verify.skip?(options[:env])

      model = options[:model]
      attribute = options[:attribute] || :base

      begin
        verified = if response_token.empty? || response_token.length > G_RESPONSE_LIMIT
          false
        else
          @recaptcha_verify_result = result = yield
          recaptcha_logger.debug "Result: " + (result.valid? ? 'valid' : "errors: #{result.errors}")
          result.valid?
        end

        if verified
          flash.delete(:recaptcha_error) if recaptcha_flash_supported? && !model
          if version == :v3
            result
          else
            true
          end
        else
          recaptcha_error(
            model,
            attribute,
            options[:message],
            "recaptcha.errors.verification_failed",
            "reCAPTCHA verification failed, please try again."
          )
          false
        end
      rescue Timeout::Error
        if Recaptcha.configuration.handle_timeouts_gracefully
          recaptcha_error(
            model,
            attribute,
            options[:message],
            "recaptcha.errors.recaptcha_unreachable",
            "Oops, we failed to validate your reCAPTCHA response. Please try again."
          )
          false
        else
          raise RecaptchaError, "Recaptcha unreachable."
        end
      rescue StandardError => e
        raise RecaptchaError, e.message, e.backtrace
      end
    end

    # Your API key can be specified in the +options+ hash or preferably
    # using the Configuration.
    #
    # @return [Boolean] whether it was able to successfully verify the response token.
    # If this is false, you can check @recaptcha_verify_result.errors to see why it failed, or
    # @recaptcha_verify_result.response to get access to the response from reCAPTCHA.
    def verify_recaptcha_v2(options = {})
      options = {model: options} unless options.is_a? Hash
      response_token = options[:response] || params['g-recaptcha-response'].to_s

      _verify_recaptcha(:v2, response_token, options.freeze) do
        response = recaptcha_verify_via_api_v2_call(request, response_token, options)
        VerifyResultV2.new(response, options[:hostname])
      end
    end
    alias_method :verify_recaptcha, :verify_recaptcha_v2

    def verify_recaptcha!(options = {})
      verify_recaptcha(options) || raise(VerifyError)
    end

    # Unlike the v2 API, the reCAPTCHA v3 API is not binary (is not simplify verified/success or
    # not). The v3 API returns a score, so rather than returning a boolean like
    # `verify_recaptcha_v2` does, `verify_recaptcha_v3` returns a `VerifyResult` which has a `score`
    # method on it. The `VerifyResult` object also gives you access to `error_codes` and anything
    # else returned in the [API
    # response](https://developers.google.com/recaptcha/docs/v3#site-verify-response).
    #
    # @return [Recaptcha::Verify::VerifyResult]
    def verify_recaptcha_v3(options = {})
      options.key?(:action) || raise(Recaptcha::RecaptchaError, 'action is required')
      action = options[:action]
      response_token = options[:response] || get_response_token_for_action(action)

      _verify_recaptcha(:v3, response_token, options.freeze) do
        response = recaptcha_verify_via_api_v3_call(request, response_token, options)
        VerifyResultV3.new(response, options[:hostname], action)
      end
    end

    # Expects params['g-recaptcha-response'] to be a hash with the action name(s) as keys, but also
    # works if a single response token is passed as a value instead of a hash.
    def get_response_token_for_action(action)
      response_param = params['g-recaptcha-response']
      if response_param.respond_to?(:to_h) # Includes ActionController::Parameters
        response_param[action]&.to_s
      else
        response_param
      end
    end

    # rubocop:disable Style/SafeNavigation
    def verify_recaptcha_v3!(options = {})
      result = verify_recaptcha_v3(options)
      # result could be false or a VerifyResult
      unless result && result.valid?
        if @recaptcha_verify_result
          raise(VerifyError, @recaptcha_verify_result.errors.to_sentence)
        else
          raise(VerifyError)
        end
      end
      result
    end
    # rubocop:enable Style/SafeNavigation

    def self.skip?(env)
      env ||= ENV['RAILS_ENV'] || ENV['RACK_ENV'] || (Rails.env if defined? Rails.env)
      Recaptcha.configuration.skip_verify_env.include? env
    end

    private

    # @return [Recaptcha::Verify::VerifyResponse]
    def recaptcha_verify_via_api_v2_call(request, response_token, options)
      secret_key = options[:secret_key] || Recaptcha.configuration.secret_key_v2!
      recaptcha_verify_via_api_call(request, response_token, secret_key, options)
    end

    # @return [Recaptcha::Verify::VerifyResponse]
    def recaptcha_verify_via_api_v3_call(request, response_token, options)
      secret_key = options[:secret_key] || Recaptcha.configuration.secret_key_v3!
      recaptcha_verify_via_api_call(request, response_token, secret_key, options)
    end

    # @return [Recaptcha::Verify::VerifyResponse]
    def recaptcha_verify_via_api_call(request, response_token, secret_key, options)
      request_hash = {
        "secret" => secret_key,
        "response" => response_token
      }

      unless options[:skip_remote_ip]
        remoteip = (request.respond_to?(:remote_ip) && request.remote_ip) || (env && env['REMOTE_ADDR'])
        request_hash["remoteip"] = remoteip.to_s
      end

      Recaptcha::Verify.get(request_hash, options)
    end

    def recaptcha_error(model, attribute, message, key, default)
      message ||= Recaptcha.i18n(key, default)
      if model
        model.errors.add attribute, message
      else
        flash[:recaptcha_error] = message if recaptcha_flash_supported?
      end
    end

    def recaptcha_flash_supported?
      request.respond_to?(:format) && request.format == :html && respond_to?(:flash)
    end

    def recaptcha_logger
      Recaptcha.configuration.logger
    end

    class VerifyError < Recaptcha::RecaptchaError
    end
  end
end
