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

# --- taint pack: request data reaching sinks through a local variable ---
class ReportsController < ApplicationController
  def search
    name = params[:name]
    # VULN: ruby.taint-sql
    @rows = User.where("name = '#{name}'")

    host = params[:host]
    # VULN: ruby.taint-command
    ok = system("ping -c 1 " + host)

    tpl = params[:template]
    # VULN: ruby.taint-template-injection
    body = ERB.new("#{tpl}").result(binding)

    path = params[:file]
    # VULN: ruby.taint-file-read
    data = File.read("/var/reports/#{path}")

    blob = cookies[:state]
    # VULN: ruby.taint-deserialize
    state = Marshal.load(blob)

    nxt = params[:next]
    # VULN: ruby.taint-open-redirect
    redirect_to nxt
  end
end
