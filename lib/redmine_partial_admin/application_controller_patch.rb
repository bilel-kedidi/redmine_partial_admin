require_dependency 'application_controller'

module RedminePartialAdmin
  module ApplicationControllerPatch
    def self.included(base)
      base.send(:include, InstanceMethods)
      base.class_eval do
        alias_method :require_admin_without_partial_admin, :require_admin
        alias_method :require_admin, :require_admin_with_partial_admin

        alias_method :require_admin_or_api_request_without_partial_admin, :require_admin_or_api_request
        alias_method :require_admin_or_api_request, :require_admin_or_api_request_with_partial_admin
      end
    end

    module InstanceMethods
      def require_admin_with_partial_admin
        return unless require_login
        if !User.current.admin? && !(User.current.partial_admin? && ( params[:controller] == 'admin' || User.current.access.keys.include?(params[:controller])))
          render_403
          return false
        end
        true
      end

      def require_admin_or_api_request_with_partial_admin
        if User.current.partial_admin?
          if  User.current.access.keys.include?(params[:controller])
            true
          else
            deny_access
          end
        else
          require_admin_or_api_request_without_partial_admin
        end
      end
    end
  end
end

ApplicationController.send(:include, RedminePartialAdmin::ApplicationControllerPatch)

