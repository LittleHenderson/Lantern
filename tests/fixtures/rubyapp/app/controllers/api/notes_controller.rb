module Api
  class NotesController < ApplicationController
    skip_before_action :authenticate_user!, only: [:destroy]
    def index
      @svc = NoteService.new
      render json: @svc.all
    end
    def show
      render json: Note.find(params[:id])
    end
    def search
      q = params[:q]
      render json: Note.where("title LIKE '%#{q}%'")
    end
    def destroy
      note = Note.find(params[:id])
      note.destroy
      cleanup
      head :no_content
    end
    private
    def cleanup
      helper_thing
    end
  end
end
