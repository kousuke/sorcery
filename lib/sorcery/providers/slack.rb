module Sorcery
  module Providers
    # This class adds support for OAuth with slack.com.

    class Slack < Base
      include Protocols::Oauth2

      attr_accessor :auth_path, :scope, :token_url, :user_info_path, :team_id

      def initialize
        super

        @scope          = 'identity.basic, identity.email'
        @site           = 'https://slack.com/'
        @user_info_path = 'https://slack.com/api/users.identity'
        @auth_path      = '/oauth/authorize'
        @token_url      = '/api/oauth.access'
      end

      def get_user_hash(access_token)
        response = access_token.get(user_info_path, params: { token: access_token.token })
        auth_hash(access_token).tap do |h|
          h[:user_info] = JSON.parse(response.body)
          h[:user_info]['email'] = h[:user_info]['user']['email']
          h[:uid] = h[:user_info]['user']['id']
        end
      end

      # calculates and returns the url to which the user should be redirected,
      # to get authenticated at the external provider's site.
      def login_url(_params, _session)
        @state = SecureRandom.hex(16)
        authorize_url({authorize_url: auth_path})
      end

      # tries to login the user from access token
      def process_callback(params, _session)
        raise 'Invalid state. Potential Cross Site Forgery. ' + params[:state] if params[:state] != state
        args = {}.tap do |a|
          a[:code] = params[:code] if params[:code]
        end

        access_token = get_access_token(args, token_url: token_url, token_method: :post)
        if team_id 
          raise 'No team id found. ' unless access_token['team'].present? || access_token['team']['id'].present? 
          raise 'Invalid team. Potential miss setting. ' if access_token['team']['id'] != team_id 
        end
        access_token
      end

      def authorize_url(options = {})
        super(options)
      end
    end
  end
end
