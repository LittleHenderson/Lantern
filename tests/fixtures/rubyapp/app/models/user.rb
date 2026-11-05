require "digest"
class User < ApplicationRecord
  def self.digest_password(password)
    Digest::MD5.hexdigest(password)
  end
end
