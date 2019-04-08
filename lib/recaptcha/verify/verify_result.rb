# frozen_string_literal: true

require 'active_support/core_ext/module/delegation'

module Recaptcha
  module Verify
    # Represents the result of us verifying that the verify response is valid against our
    # {Configuration}.
    #
    # This is mostly a wrapper for {VerifyResponse} but depends also upon comparing it to our
    # configured hostname, etc.
    #
    class VerifyResult
      attr_reader :response
      attr_reader :errors

      def initialize(verify_response, hostname)
        @response = verify_response
        @expected_hostname = hostname || Recaptcha.configuration.hostname
      end

      delegate :json, :success?, :challenge_ts, :hostname,
        :error_codes, :timeout_or_duplicate?,
        to: :response, allow_nil: true

      # Returns true if it passes all internal validations, else false.
      # Can check `errors` to see which validation failed if valid? returns false.
      def valid?
        @errors = []
        unless response.success?
          @errors << error_codes&.join(',')
          return false
        end
        unless hostname_valid?
          @errors << "Hostname '#{hostname}' did not match expected hostname"
        end
        @errors.none?
      end

      def hostname_valid?
        case @expected_hostname
        when nil, FalseClass then true
        when String then @expected_hostname == hostname
        else @expected_hostname.call(hostname)
        end
      end
    end

    class VerifyResultV2 < VerifyResult
    end

    class VerifyResultV3 < VerifyResult
      def initialize(verify_response, hostname, action)
        super(verify_response, hostname)
        @expected_action = action
      end

      delegate :score, :action,
        to: :response, allow_nil: true

      def valid?
        super
        return false unless response.success?

        unless action_valid?
          @errors << "Action '#{action}' did not match '#{@expected_action}'"
        end
        @errors.none?
      end

      def action_valid?
        case @expected_action
        when nil, FalseClass then true
        else action == @expected_action
        end
      end
    end
  end
end
