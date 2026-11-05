class PruneJob < ApplicationJob
  def perform
    NoteService.new.all
  end
end
