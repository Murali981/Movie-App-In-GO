package main

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/golang-jwt/jwt/v4"
)

//// Every handler in the go world takes two arguments

func (app *application) Home(w http.ResponseWriter , r *http.Request) { /// It is the default route to our API
	var payload = struct {   /// Here we have created a variable payload
		Status string `json:"status"`
		Message string  `json:"message"`
		Version string `json:"version"`
	} {   //// In this step we have populated the variable payload....
		Status : "active",
		Message : "Go movies up and running",
		Version : "1.0.0",
	}

   _ = app.writeJSON(w , http.StatusOK , payload)

}


func (app *application) AllMovies(w http.ResponseWriter , r *http.Request) {
	// var movies []models.Movie

	// rd , _ := time.Parse("2006-01-02" , "1986-03-07")


	// highlander := models.Movie {
	// 	ID : 1,
	// 	TITLE: "Highlander",
	// 	ReleaseDate: rd,
	// 	MPAARating: "R",
	// 	RunTime : 116,
	// 	Description: "A very nice movie",
	// 	CreatedAt: time.Now(),
	// 	UpdatedAt: time.Now(),
	// }


	


    //  movies = append(movies , highlander)


	//  rd , _ = time.Parse("2006-01-02" , "1981-06-12")

	//  rotla := models.Movie {
	// 	ID : 2,
	// 	TITLE: "Raiders of the last arc",
	// 	ReleaseDate: rd,
	// 	MPAARating: "PG-13",
	// 	RunTime : 115,
	// 	Description: "A very good movie",
	// 	CreatedAt: time.Now(),
	// 	UpdatedAt: time.Now(),
	// }

	// movies = append(movies , rotla)


	 movies , err := app.DB.AllMovies()

	 if err != nil {
		app.errorJSON(w,err)
		return
	 }



	 _ = app.writeJSON(w , http.StatusOK , movies)

}


 func (app *application) authenticate(w http.ResponseWriter, r *http.Request) {
	/// Read the json payload

	var requestPayload struct {  // We have read the JSON payload here...
		Email string `json:"email"`
		Password string `json:"password"`
	}


	 err := app.readJSON(w,r, &requestPayload)

	 if err != nil {
		app.errorJSON(w,err,http.StatusBadRequest)
		return
	 }


	/// Validate the user against the database 
	user , err := app.DB.GetUserByEmail(requestPayload.Email)

	if err != nil {
		app.errorJSON(w , errors.New("invalid credentials") , http.StatusBadRequest)
		return
	}

	/// Check the password  which should match with the password that is stored in the database....
	valid , err := user.PasswordMatches(requestPayload.Password)

	if err != nil || !valid {
		app.errorJSON(w,errors.New("invalid credentials") , http.StatusBadRequest)
		return
	}


	/// Create a JWT User....
	u := jwtUser {
		ID : user.ID,
		FirstName : user.FirstName ,
		LastName : user.LastName,
	}


	  //// Generate tokens...
	  tokens , err := app.auth.GenerateTokenPair(&u)
	  if err != nil {
		app.errorJSON(w,err)
		return
	  }



	  refreshCookie := app.auth.GetRefreshCookie(tokens.RefreshToken)

	  http.SetCookie(w,refreshCookie)


	//   w.Write([]byte(tokens.Token)) /// This is writing the JWT to the browser window

	app.writeJSON(w,http.StatusAccepted , tokens)
 }


  func (app *application)  refreshToken(w http.ResponseWriter , r *http.Request) {
	for _,cookie := range r.Cookies() {
		if cookie.Name == app.auth.CookieName {
			claims := &Claims{}
			refreshToken := cookie.Value


			// Parse the token to get the claims
			_ , err := jwt.ParseWithClaims(refreshToken , claims , func(token *jwt.Token) (interface{} , error) {
				return []byte(app.JWTSecret) , nil
			})

			if err != nil {
				app.errorJSON(w , errors.New("unauthorized") , http.StatusUnauthorized)
				return
			}


			//// Get the userId from the token claims....
			userID , err := strconv.Atoi(claims.Subject)

			if err != nil {
				app.errorJSON(w , errors.New("unknown user") , http.StatusUnauthorized)
				return
			}


			user , err := app.DB.GetUserByID(userID)

			
			if err != nil {
				app.errorJSON(w , errors.New("unknown user") , http.StatusUnauthorized)
				return
			}

			u := jwtUser{
				ID : user.ID,
				FirstName : user.FirstName,
				LastName : user.LastName,
			}

			tokenPairs , err := app.auth.GenerateTokenPair(&u)
			
			if err != nil {
				app.errorJSON(w , errors.New("error generating tokens") , http.StatusUnauthorized)
				return
			}


			http.SetCookie(w , app.auth.GetRefreshCookie(tokenPairs.RefreshToken))

			app.writeJSON(w , http.StatusOK , tokenPairs) 
		}
	}
  }


  func (app *application)  logout(w http.ResponseWriter , r *http.Request)  {
	  http.SetCookie(w , app.auth.GetExpiredRefreshCookie())
	  w.WriteHeader(http.StatusAccepted)
  }


  func (app *application) MovieCatalog(w http.ResponseWriter , r *http.Request) {
	movies , err := app.DB.AllMovies()

	if err != nil {
	   app.errorJSON(w,err)
	   return
	}



	_ = app.writeJSON(w , http.StatusOK , movies)
  }