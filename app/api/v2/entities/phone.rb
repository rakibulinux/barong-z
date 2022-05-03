# frozen_string_literal: true

module API
  module V2
    module Entities
      # Phone request response
      class Phone < API::V2::Entities::Base
        expose :number,
               documentation: {
                type: 'String',
                desc: 'Submasked phone number'
               } do |phone|
                phone.number
               end

        expose :validated_at,
               documentation: {
                type: 'Datetime',
                desc: 'Phone validation date'
               } do |phone|
                return phone.code.validated_at if phone.code
               end
      end
    end
  end
end
