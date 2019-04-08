# frozen_string_literal: true

require 'logger'

module Recaptcha
  # This class enables detailed configuration of the recaptcha services.
  #
  # By calling
  #
  #   Recaptcha.configuration # => instance of Recaptcha::Configuration
  #
  # or
  #   Recaptcha.configure do |config|
  #     config # => instance of Recaptcha::Configuration
  #   end
  #
  # you are able to perform configuration updates.
  #
  # Your are able to customize all attributes listed below. All values have
  # sensitive default and will very likely not need to be changed.
  #
  # Please note that the site and secret key for the reCAPTCHA API Access
  # have no useful default value. The keys may be set via enviroment variables
  # or using this configuration. Settings within this configuration always take
  # precedence.
  #
  # Setting the keys with this Configuration:
  #
  #   Recaptcha.configure do |config|
  #     config.site_key   = '6Lc6BAAAAAAAAChqRbQZcn_yyyyyyyyyyyyyyyyy'
  #     config.secret_key = '6Lc6BAAAAAAAAKN3DRm6VA_xxxxxxxxxxxxxxxxx'
  #   end
  #
  # If you only intend to use one of the API versions, that's all you have to do. If you would like
  # to use both v2 and v3 APIs, then you need a different key for each. You can configure keys for
  # both like this:
  #
  #   Recaptcha.configure do |config|
  #     config.site_key_v2   = '6Lc6BAAAAAAAAChqRbQZcn_yyyyyyyyyyyyyyyy2'
  #     config.secret_key_v2 = '6Lc6BAAAAAAAAKN3DRm6VA_xxxxxxxxxxxxxxxx2'
  #     config.site_key_v3   = '6Lc6BAAAAAAAAChqRbQZcn_yyyyyyyyyyyyyyyy3'
  #     config.secret_key_v3 = '6Lc6BAAAAAAAAKN3DRm6VA_xxxxxxxxxxxxxxxx3'
  #   end
  #
  # Why would you want to do that? Because there are legitimate use cases for both. And v2 is not
  # going away! See https://developers.google.com/recaptcha/docs/faq#should-i-use-recaptcha-v2-or-v3.
  #
  class Configuration
    attr_accessor :skip_verify_env, :proxy, :handle_timeouts_gracefully, :hostname, :logger
    attr_accessor :site_key,    :secret_key,
      :site_key_v2, :secret_key_v2,
      :site_key_v3, :secret_key_v3
    attr_writer :api_server_url, :verify_url

    def initialize #:nodoc:
      @skip_verify_env = %w[test cucumber]
      @handle_timeouts_gracefully = HANDLE_TIMEOUTS_GRACEFULLY

      @site_key      = ENV['RECAPTCHA_SITE_KEY']
      @secret_key    = ENV['RECAPTCHA_SECRET_KEY']
      @site_key_v2   = ENV['RECAPTCHA_SITE_KEY_V2']
      @secret_key_v2 = ENV['RECAPTCHA_SECRET_KEY_V2']
      @site_key_v3   = ENV['RECAPTCHA_SITE_KEY_V3']
      @secret_key_v3 = ENV['RECAPTCHA_SECRET_KEY_V3']

      @verify_url = nil
      @api_server_url = nil
      @logger = Logger.new('/dev/null')
    end

    def site_key!
      site_key || raise(RecaptchaError, "No site key specified.")
    end

    def site_key_v2!
      site_key_v2 || site_key || raise(RecaptchaError, "No site key specified.")
    end

    def site_key_v3!
      site_key_v3 || site_key || raise(RecaptchaError, "No site key specified.")
    end

    def secret_key!
      secret_key || raise(RecaptchaError, "No secret key specified.")
    end

    def secret_key_v2!
      secret_key_v2 || secret_key || raise(RecaptchaError, "No secret key specified.")
    end

    def secret_key_v3!
      secret_key_v3 || secret_key || raise(RecaptchaError, "No secret key specified.")
    end

    def api_server_url
      @api_server_url || CONFIG.fetch('server_url')
    end

    def verify_url
      @verify_url || CONFIG.fetch('verify_url')
    end
  end
end
