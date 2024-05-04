package models

import "time"

type Movie struct {
	ID          int    `json:"id"`
	TITLE       string `json:"title"`
	ReleaseDate time.Time `json:"release_date"`
	RunTime int `json:"runtime"`
	MPAARating string `json:"mpaa_rating"`
	Description string `json:"description"`
	Image string `json:"image"`
	CreatedAt time.Time `json:"-"`
	UpdatedAt time.Time `json:"-"`
}