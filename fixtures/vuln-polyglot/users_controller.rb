# VULN pack: php-ruby
class UsersController < ApplicationController
  def update
    # VULN: ruby.mass-assignment
    @user = User.new(params[:user])

    # VULN: ruby.send-dynamic
    target.send(params[:method])

    # VULN: ruby.constantize-input
    klass = params[:type].constantize

    # VULN: ruby.render-inline
    render inline: "Hello #{params[:name]}"
  end
end
