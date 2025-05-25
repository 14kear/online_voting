package routes

import (
	"github.com/14kear/online_voting/voting-service/internal/handlers"
	"github.com/gin-gonic/gin"
)

func RegisterPublicRoutes(rg *gin.RouterGroup, handler *handlers.VotingHandler) {
	{
		rg.GET("/polls", handler.GetPolls)
		rg.GET("/polls/:id", handler.GetPollByID)

		rg.GET("/polls/:id/options", handler.GetOptionsByPollID)

		rg.GET("/results/:id", handler.GetResultByID)
		rg.GET("/results/poll/:pollID", handler.GetResultsByPollID)
		rg.GET("/results", handler.GetResults)

		rg.GET("/logs", handler.GetLogs)
	}
}

func RegisterPrivateRoutes(rg *gin.RouterGroup, handler *handlers.VotingHandler) {
	{
		rg.POST("/polls", handler.CreatePoll)
		rg.DELETE("/polls/:id", handler.DeletePoll)

		rg.POST("/polls/:id/options", handler.CreateOption)
		rg.DELETE("polls/:id/options/:optionID", handler.DeleteOption)

		rg.POST("results", handler.SaveResult)
		rg.DELETE("results/:id", handler.DeleteResult)
	}
}
