require "net/http"
class NoteService
  def initialize
    @client = Faraday.new(url: "https://hooks.example.com")
  end
  def all
    Note.all.to_a
  end
  def notify(name)
    HTTParty.post("https://hooks.example.com/notify/#{name}")
    Net::HTTP.get(URI.parse("https://example.com/x")).strip
  end
end
