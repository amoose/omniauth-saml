require 'omniauth'
require 'ruby-saml'

module OmniAuth
  module Strategies
    class SAML
      include OmniAuth::Strategy

      option :name_identifier_format, nil
      option :idp_sso_target_url_runtime_params, {}
      option :allowed_clock_drift, nil

      def request_phase
        options[:assertion_consumer_service_url] ||= callback_url

        runtime_request_parameters = options.delete(:idp_sso_target_url_runtime_params)

        additional_params = {}
        runtime_request_parameters.each_pair do |request_param_key, mapped_param_key|
          additional_params[mapped_param_key] = request.params[request_param_key.to_s] if request.params.has_key?(request_param_key.to_s)
        end if runtime_request_parameters


        authn_request = OneLogin::RubySaml::Authrequest.new
        settings = OneLogin::RubySaml::Settings.new(options)

        if settings.assertion_consumer_service_binding and 
          settings.assertion_consumer_service_binding.match(/HTTP-POST/)
            idp_sso_target_url = settings.idp_sso_target_url
            saml_request_doc = authn_request.create_document(settings)
            html = build_html(idp_sso_target_url, 'SAMLRequest', saml_request_doc)
            Rack::Response.new(html, 200, { "Content-Type" => "text/html" }).finish
        else
          idp_sso_target_url = authn_request.create(settings, additional_params)
          redirect idp_sso_target_url
        end
      end

      def callback_phase
        unless request.params['SAMLResponse']
          raise OmniAuth::Strategies::SAML::ValidationError.new("SAML response missing")
        end

        # Call a fingerprint validation method if there's one
        if options.idp_cert_fingerprint_validator
          fingerprint_exists = options.idp_cert_fingerprint_validator[response_fingerprint]
          unless fingerprint_exists
            raise OmniAuth::Strategies::SAML::ValidationError.new("Non-existent fingerprint")
          end
          # id_cert_fingerprint becomes the given fingerprint if it exists
          options.idp_cert_fingerprint = fingerprint_exists
        end

        response = OneLogin::RubySaml::Response.new(request.params['SAMLResponse'], options)
        response.settings = OneLogin::RubySaml::Settings.new(options)

        @name_id = response.name_id
        @attributes = response.attributes

        if @name_id.nil? || @name_id.empty?
          raise OmniAuth::Strategies::SAML::ValidationError.new("SAML response missing 'name_id'")
        end

        response.validate!

        super
      rescue OmniAuth::Strategies::SAML::ValidationError
        fail!(:invalid_ticket, $!)
      rescue OneLogin::RubySaml::ValidationError
        fail!(:invalid_ticket, $!)
      rescue REXML::ParseException
        request.params['SAMLResponse'] = clean_newlines
        retry
      end

      # remove newline characters if they're included in the SAMLResponse
      def clean_newlines
        if request.params['SAMLResponse'].include?('\\r\\n')
          request.params['SAMLResponse'].gsub('\\r\\n', '')
        end
      end

      # Obtain an idp certificate fingerprint from the response.
      def response_fingerprint
        response = request.params['SAMLResponse']
        response = (response =~ /^</) ? response : Base64.decode64(response)
        document = XMLSecurity::SignedDocument::new(response)
        cert_element = REXML::XPath.first(document, "//ds:X509Certificate", { "ds"=> 'http://www.w3.org/2000/09/xmldsig#' })
        base64_cert = cert_element.text
        cert_text = Base64.decode64(base64_cert)
        cert = OpenSSL::X509::Certificate.new(cert_text)
        Digest::SHA1.hexdigest(cert.to_der).upcase.scan(/../).join(':')
      end

      def other_phase
        if on_path?("#{request_path}/metadata")
          # omniauth does not set the strategy on the other_phase
          @env['omniauth.strategy'] ||= self
          setup_phase
          
          response = OneLogin::RubySaml::Metadata.new
          settings = OneLogin::RubySaml::Settings.new(options)

          Rack::Response.new(response.generate(settings), 200, { "Content-Type" => "application/xml" }).finish
        else
          call_app!
        end
      end

      def build_html(action_url, type, message)
        string = <<EOF  
<html>
<head>
  <meta charset="utf-8" />
</head>
<body onload="document.forms[0].submit();" style="visibility:hidden;">
  <form action="%%action_url%%" method="POST">
  <input type="hidden" value="%%message%%" name="%%type%%" />
  <input type="submit" value="Submit" />
</form>
</body>
</html>
EOF


        html = REXML::Document.new string
        raw_html = html.to_s
        raw_html.gsub!('%%action_url%%', action_url)
        raw_html.gsub!('%%type%%', type)
        raw_html.gsub!('%%message%%', message.to_s)

        raw_html
      end

      uid { @name_id }

      info do
        {
          :email => @attributes[:emailAddress],
          :cis_uuid => @attributes[:cisUUID],
          :groups => @attributes[:groups],
          :first_name => @attributes[:givenName],
          :last_name => @attributes[:sn]
        }
      end

      extra { { :raw_info => @attributes } }
    end
  end
end

OmniAuth.config.add_camelization 'saml', 'SAML'
