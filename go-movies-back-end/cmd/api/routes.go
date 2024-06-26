package main

import (
	"net/http"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/chi/v5"
)

func (app *application) routes() http.Handler {

   //// Create a router MUX

   mux := chi.NewRouter()



   mux.Use(middleware.Recoverer)

   mux.Use(app.enableCORS)


   mux.Get("/" , app.Home)  /// When you got a GET request to this path then go to the handler app.Home

   mux.Post("/authenticate" , app.authenticate)

   mux.Get("/refresh" , app.refreshToken)

   mux.Get("/logout" , app.logout)


   mux.Get("/movies" , app.AllMovies) ///  When you got a GET request to this path which is /movies then go to the handler app.AllMovies


   mux.Route("/admin" , func(mux chi.Router) {
      mux.Use(app.authRequired)

      mux.Get("/movies" , app.MovieCatalog)
   })


  




   return mux


}