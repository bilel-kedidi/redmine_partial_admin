require_dependency 'user'

module RedminePartialAdminPatch
  module UserPatch
    def self.included(base)
      base.send(:include, InstanceMethods)
      base.class_eval do
        serialize :access
        safe_attributes 'partial_admin',  'access'

        alias_method :allowed_to_without_partial_admin?, :allowed_to?
        alias_method :allowed_to? , :allowed_to_with_partial_admin?
      end
    end

    module InstanceMethods
      def get_controllers_name(action)
        if action.is_a? Hash
          [action[:controller]]
        else
          action = Redmine::AccessControl.permissions.detect{|p| p.name == action }
          action.present? ? action.actions.map{|location| location.split('/').first}.uniq : []
        end

      end

      def allowed_to_with_partial_admin?(action, context, options={}, &block)
        if context && context.is_a?(Project)
          return false unless context.allows_to?(action)
          # Admin users are authorized for anything else
          return true if admin?
          return true if partial_admin? && (User.current.access.keys & get_controllers_name(action)).present?

          roles = roles_for_project(context)
          return false unless roles
          roles.any? {|role|
            (context.is_public? || role.member?) &&
                role.allowed_to?(action) &&
                (block_given? ? yield(role, self) : true)
          }
        elsif context && context.is_a?(Array)
          if context.empty?
            false
          else
            # Authorize if user is authorized on every element of the array
            context.map {|project| allowed_to?(action, project, options, &block)}.reduce(:&)
          end
        elsif context
          raise ArgumentError.new("#allowed_to? context argument must be a Project, an Array of projects or nil")
        elsif options[:global]
          # Admin users are always authorized
          return true if admin?
          return true if partial_admin? && (User.current.access.keys & get_controllers_name(action)).present?

          # authorize if user has at least one role that has this permission
          roles = self.roles.to_a | [builtin_role]
          roles.any? {|role|
            role.allowed_to?(action) &&
                (block_given? ? yield(role, self) : true)
          }
        else
          false
        end
      end
    end
  end
end

User.send(:include, RedminePartialAdminPatch::UserPatch)

