Rails.application.routes.draw do
  root "home#index"
  namespace :api do
    resources :notes, only: [:index, :show, :destroy] do
      collection do
        get :search
      end
    end
    get "export", to: "exports#run"
  end
  post "/login" => "sessions#create"
end
