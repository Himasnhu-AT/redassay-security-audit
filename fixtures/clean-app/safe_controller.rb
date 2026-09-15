# Control: request data handled safely. Nothing here should be flagged.
class SafeController < ApplicationController
  def index
    # Parameterised query: the value is a bound parameter, not interpolated.
    name = params[:name]
    @users = User.where("name = ?", name)

    # Hash condition: also parameterised.
    @posts = Post.where(author: params[:author])

    # Numeric coercion neutralises the value for every sink.
    page = params[:page].to_i
    @rows = Record.where("page = #{page}")

    # Allowlisted filename, resolved and confined.
    safe = File.basename(params[:file])
    @doc = File.read("/var/docs/#{safe}")

    # Output is HTML-escaped before it is marked safe.
    @greeting = ERB::Util.html_escape(params[:q]).html_safe

    # No request data in the command; fixed arguments, array form, no shell.
    system("ls", "-la", "/tmp")

    # Redirect to a fixed, relative path.
    redirect_to "/dashboard"
  end
end
