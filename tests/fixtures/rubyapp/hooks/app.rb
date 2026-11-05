require "sinatra"

def helper_thing
  1
end

get "/ping" do
  helper_thing
  "pong"
end

post "/hooks/run" do
  system("echo #{params[:x]}")
end
