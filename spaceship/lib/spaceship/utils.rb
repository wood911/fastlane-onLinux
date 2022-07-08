module Spaceship
  class Utils
    def self.error_callback(code, msg, data)
      url = ENV["ERROR_CALLBACK_URL"].to_s
      unless url.empty?
        uri = URI.parse(url)
        hash = eval(ENV["FL_RESIGN_PARAMS"] || "")
        req = Net::HTTP::Post.new(uri.path, { 'Content-Type' => 'application/json' })
        req.body = {code: code, msg: msg, data: {params: hash, body: data}}.to_json
        http = Net::HTTP.new(uri.host, uri.port)
        http.request(req)
      end
    end
  end
end




