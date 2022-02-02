# frozen_string_literal: true

require_dependency 'barong/jwt'

module API::V2
  module Identity
    class Sessions < Grape::API
      helpers do
        def get_user(email)
          user = User.find_by(email: email)
          error!({ errors: ['identity.session.invalid_params'] }, 401) unless user

          if user.state == 'banned'
            login_error!(reason: 'Your account is banned', error_code: 401,
                         user: user.id, action: 'login', result: 'failed', error_text: 'banned')
          end

          if user.state == 'deleted'
            login_error!(reason: 'Your account is deleted', error_code: 401,
                         user: user.id, action: 'login', result: 'failed', error_text: 'deleted')
          end

          # if user is not active or pending, then return 401
          unless user.state.in?(%w[active pending])
            login_error!(reason: 'Your account is not active', error_code: 401,
                         user: user.id, action: 'login', result: 'failed', error_text: 'not_active')
          end
          user
        end
      end

      desc 'Session related routes'
      resource :sessions do
        desc 'Start a new session',
             failure: [
               { code: 400, message: 'Required params are empty' },
               { code: 404, message: 'Record is not found' }
             ]
        params do
          requires :email
          requires :password
          optional :email_code,
                   type: String,
                   desc: 'Code from Email'
          optional :phone_code,
                   type: String,
                   desc: 'Phone from Email'
          optional :captcha_response,
                   types: { value: [String, Hash], message: 'identity.session.invalid_captcha_format' },
                   desc: 'Response from captcha widget'
          optional :otp_code,
                   type: String,
                   desc: 'Code from Google Authenticator'
        end
        post do
          verify_captcha!(response: params['captcha_response'], endpoint: 'session_create')

          declared_params = declared(params, include_missing: false)
          user = get_user(declared_params[:email])

          unless user.authenticate(declared_params[:password])
            login_error!(reason: 'Invalid Email or Password', error_code: 401, user: user.id,
                         action: 'login', result: 'failed', error_text: 'invalid_params')
          end

          if declared_params[:email_code].blank?
            login_error!(reason: 'Email code is missing', error_code: 401, user: user.id,
              action: 'login', result: 'failed', error_text: 'missing_email_code')
          end

          email_code = Code.pending.find_by(user: user, code_type: 'email', category: 'login')

          unless email_code
            login_error!(reason: 'Email code invalid', error_code: 422, user: user.id,
                         action: 'login', result: 'failed', error_text: 'email_code_invalid')
          end

          unless email_code.verify_code!(declared_params[:email_code])
            email_code.save!
            login_error!(reason: 'Email code invalid', error_code: 422, user: user.id,
                         action: 'login', result: 'failed', error_text: 'email_code_invalid')
          end

          if user.phone
            if declared_params[:phone_code].blank?
              login_error!(reason: 'Phone code is missing', error_code: 401, user: user.id,
                action: 'login', result: 'failed', error_text: 'missing_phone_code')
            end

            phone_code = Code.pending.find_by(user: user, code_type: 'phone', category: 'login')

            unless phone_code
              login_error!(reason: 'Phone code invalid', error_code: 400, user: user.id,
                         action: 'login', result: 'failed', error_text: 'phone_code_invalid')
            end

            unless phone_code.verify_code!(declared(params)[:phone_code])
              login_error!(reason: 'Phone code invalid', error_code: 422, user: user.id,
                         action: 'login', result: 'failed', error_text: 'phone_code_invalid')
            end
          end

          if user.otp
            error!({ errors: ['identity.session.missing_otp'] }, 401) if declared_params[:otp_code].blank?
            unless TOTPService.validate?(user.uid, declared_params[:otp_code])
              login_error!(reason: 'OTP code is invalid', error_code: 403,
                           user: user.id, action: 'login::2fa', result: 'failed', error_text: 'invalid_otp')
            end

            activity_record(user: user.id, action: 'login::2fa', result: 'succeed', topic: 'session')
          else
            activity_record(user: user.id, action: 'login', result: 'succeed', topic: 'session')
          end

          csrf_token = open_session(user)
          publish_session_create(user)

          present user, with: API::V2::Entities::UserWithFullInfo, csrf_token: csrf_token
          status(200)
        end

        desc 'Request code for login'
        params do
          requires :email
          requires :type,
                   type: String,
                   allow_blank: false,
                   values: { value: -> { Code::TYPES }, message: 'identity.session.invalid_type'},
                   desc: "Type of code"
        end
        post '/generate_code' do
          declared_params = declared(params, include_missing: false)
          user = get_user(declared_params[:email])

          return status 201 if declared_params[:type] == 'phone' && user.phone.nil?

          code = Code.pending.find_or_create_by(user: user, code_type: declared_params[:type], category: 'login')
          code.generate_code!

          status 201
        end

        desc 'Destroy current session',
          failure: [
            { code: 400, message: 'Required params are empty' },
            { code: 404, message: 'Record is not found' }
          ],
          success: { code: 200, message: 'Session was destroyed' }
        delete do
          user = User.find_by(uid: session[:uid])
          error!({ errors: ['identity.session.not_found'] }, 404) unless user

          activity_record(user: user.id, action: 'logout', result: 'succeed', topic: 'session')

          Barong::RedisSession.delete(user.uid, session.id.to_s)
          session.destroy

          status(200)
        end

        desc 'Auth0 authentication by id_token',
             success: { code: 200, message: 'User authenticated' },
             failure: [
               { code: 400, message: 'Required params are empty' },
               { code: 404, message: 'Record is not found' }
             ]
        params do
          requires :id_token,
                   type: String,
                   allow_blank: false,
                   desc: 'ID Token'
        end
        post '/auth0' do
          begin
            # Decode ID token to get user info
            claims = Barong::Auth0::JWT.verify(params[:id_token]).first
            error!({ errors: ['identity.session.auth0.invalid_params'] }, 401) unless claims.key?('email')
            user = User.find_by(email: claims['email'])

            # If there is no user in platform and user email verified from id_token
            # system will create user
            if user.blank? && claims['email_verified']
              user = User.create!(email: claims['email'], state: 'active')
              user.labels.create!(scope: 'private', key: 'email', value: 'verified')
            elsif claims['email_verified'] == false
              error!({ errors: ['identity.session.auth0.invalid_params'] }, 401) unless user
            end

            activity_record(user: user.id, action: 'login', result: 'succeed', topic: 'session')
            csrf_token = open_session(user)
            publish_session_create(user)

            present user, with: API::V2::Entities::UserWithFullInfo, csrf_token: csrf_token
          rescue StandardError => e
            report_exception(e)
            error!({ errors: ['identity.session.auth0.invalid_params'] }, 422)
          end
        end
      end
    end
  end
end
