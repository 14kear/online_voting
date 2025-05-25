package handlers

import (
	"github.com/14kear/online_voting/voting-service/internal/entity"
	"github.com/14kear/online_voting/voting-service/internal/services"
	"github.com/gin-gonic/gin"
	"net/http"
	"strconv"
)

type VotingHandler struct {
	votingService *services.OnlineVoting
}

type CreatePollRequest struct {
	Title       string `json:"title" binding:"required"`
	Description string `json:"description" binding:"required"`
	Status      string `json:"status"      binding:"required,oneof=active closed"`
}

type CreateOptionRequest struct {
	Text string `json:"text" binding:"required"`
}

type UpdatePollRequest struct {
	Title       string `json:"title" binding:"required"`
	Description string `json:"description" binding:"required"`
	Status      string `json:"status"      binding:"required,oneof=active closed"`
}

type UpdateOptionRequest struct {
	Text string `json:"text" binding:"required"`
}

type SaveResultRequest struct {
	PollID   int64 `json:"poll_id" binding:"required"`
	OptionID int64 `json:"option_id" binding:"required"`
}

func NewVotingHandler(votingService *services.OnlineVoting) *VotingHandler {
	return &VotingHandler{votingService: votingService}
}

func (v *VotingHandler) CreatePoll(c *gin.Context) {
	var req CreatePollRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid input"})
		return
	}

	userIDValue, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	userID, ok := userIDValue.(int64)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid user id in context"})
		return
	}

	// конвертация статуса
	var status entity.PollStatus
	switch req.Status {
	case string(entity.PollStatusActive):
		status = entity.PollStatusActive
	case string(entity.PollStatusClosed):
		status = entity.PollStatusClosed
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown status"})
		return
	}

	pollID, err := v.votingService.CreatePoll(c.Request.Context(), req.Title, req.Description, userID, status)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"poll_id": pollID})
}

func (v *VotingHandler) GetPollByID(c *gin.Context) {
	pollIDStr := c.Param("id")
	pollID, err := strconv.Atoi(pollIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid poll id"})
		return
	}

	poll, err := v.votingService.GetPollByID(c.Request.Context(), int64(pollID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"poll": poll})
}

func (v *VotingHandler) GetPolls(c *gin.Context) {
	polls, err := v.votingService.GetPolls(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"polls": polls})
}

func (v *VotingHandler) UpdatePoll(c *gin.Context) {
	var req UpdatePollRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid input"})
		return
	}

	userIDValue, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	userID, ok := userIDValue.(int64)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid user id in context"})
		return
	}

	pollIDStr := c.Param("id")
	pollID, err := strconv.Atoi(pollIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid poll id"})
		return
	}

	// конвертация статуса
	var status entity.PollStatus
	switch req.Status {
	case string(entity.PollStatusActive):
		status = entity.PollStatusActive
	case string(entity.PollStatusClosed):
		status = entity.PollStatusClosed
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown status"})
		return
	}

	err = v.votingService.UpdatePoll(c.Request.Context(), int64(pollID), req.Title, req.Description, status, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"poll_id": pollID})
}

func (v *VotingHandler) DeletePoll(c *gin.Context) {
	pollIDStr := c.Param("id")
	pollID, err := strconv.Atoi(pollIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid poll id"})
		return
	}

	userIDValue, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	userID, ok := userIDValue.(int64)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid user id in context"})
		return
	}

	err = v.votingService.DeletePoll(c.Request.Context(), int64(pollID), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusNoContent, gin.H{})
}

func (v *VotingHandler) CreateOption(c *gin.Context) {
	var req CreateOptionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid input"})
		return
	}

	userIDValue, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	userID, ok := userIDValue.(int64)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid user id in context"})
		return
	}

	pollIDStr := c.Param("id")
	pollID, err := strconv.Atoi(pollIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid poll id"})
		return
	}

	optionID, err := v.votingService.CreateOption(c.Request.Context(), int64(pollID), req.Text, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"option_id": optionID})
}

func (v *VotingHandler) GetOptionsByPollID(c *gin.Context) {
	pollIDStr := c.Param("id")
	pollID, err := strconv.Atoi(pollIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid poll id"})
		return
	}

	options, err := v.votingService.GetOptionsByPollID(c.Request.Context(), int64(pollID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"options": options})
}

func (v *VotingHandler) UpdateOption(c *gin.Context) {
	var req UpdateOptionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid input"})
		return
	}

	userIDValue, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	userID, ok := userIDValue.(int64)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid user id in context"})
		return
	}

	optionIDStr := c.Param("optionID")
	optionID, err := strconv.Atoi(optionIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid option id"})
		return
	}

	pollIDStr := c.Param("id")
	pollID, err := strconv.Atoi(pollIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid poll id"})
		return
	}

	err = v.votingService.UpdateOption(c.Request.Context(), int64(optionID), int64(pollID), req.Text, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"option_id": optionID})
}

func (v *VotingHandler) DeleteOption(c *gin.Context) {
	pollIDStr := c.Param("id")
	pollID, err := strconv.Atoi(pollIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid poll id"})
		return
	}

	optionIDStr := c.Param("optionID")
	optionID, err := strconv.Atoi(optionIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid option id"})
		return
	}

	userIDValue, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	userID, ok := userIDValue.(int64)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid user id in context"})
		return
	}

	err = v.votingService.DeleteOption(c.Request.Context(), int64(optionID), int64(pollID), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusNoContent, gin.H{})
}

func (v *VotingHandler) SaveResult(c *gin.Context) {
	var req SaveResultRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid input"})
		return
	}

	userIDVal, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	userID, ok := userIDVal.(int64)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid user id in context"})
		return
	}

	resultID, err := v.votingService.SaveResult(c.Request.Context(), req.PollID, req.OptionID, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"result_id": resultID})
}

func (v *VotingHandler) GetResultByID(c *gin.Context) {
	resultIDStr := c.Param("id")
	resultID, err := strconv.Atoi(resultIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid result id"})
		return
	}

	result, err := v.votingService.GetResultByID(c.Request.Context(), int64(resultID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"result": result})
}

func (v *VotingHandler) GetResultsByPollID(c *gin.Context) {
	pollIDStr := c.Param("pollID")
	pollID, err := strconv.Atoi(pollIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid poll id"})
		return
	}

	results, err := v.votingService.GetResultsByPollID(c.Request.Context(), int64(pollID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"results": results})
}

func (v *VotingHandler) GetResults(c *gin.Context) {
	results, err := v.votingService.GetResults(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"results": results})
}

func (v *VotingHandler) DeleteResult(c *gin.Context) {
	resultIDStr := c.Param("id")
	resultID, err := strconv.Atoi(resultIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid result id"})
		return
	}

	userIDVal, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	userID, ok := userIDVal.(int64)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid user id in context"})
		return
	}

	err = v.votingService.DeleteResult(c.Request.Context(), int64(resultID), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusNoContent, gin.H{})
}

func (v *VotingHandler) GetLogs(c *gin.Context) {
	logs, err := v.votingService.GetLogs(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"logs": logs})
}
