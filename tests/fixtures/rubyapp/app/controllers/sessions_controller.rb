class SessionsController < ApplicationController
  skip_before_action :authenticate_user!, only: [:create]
  def create
    user = User.find_by(email: params[:email])
    head :ok
  end
end
