class Api::ExportsController < ApplicationController
  def run
    name = params[:name]
    out = `tar czf /tmp/#{name}.tgz notes`
    svc = NoteService.new
    svc.notify(name)
    render plain: out
  end
end
